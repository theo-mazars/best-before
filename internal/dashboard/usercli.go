package dashboard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/theo-mazars/best-before/internal/dashboard/auth"
	"github.com/theo-mazars/best-before/internal/dashboard/store"
)

// UserCLI manages users from the terminal. Accounts never exist without
// TOTP, and every change ends the user's sessions.
type UserCLI struct {
	Config Config
	In     *os.File
	Out    io.Writer
	lines  *bufio.Scanner
}

func (u *UserCLI) Add(ctx context.Context, email, role string) error {
	if err := checkRole(role); err != nil {
		return err
	}
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || addr.Name != "" {
		return fmt.Errorf("%q is not a valid email address", email)
	}
	if err := u.needTerminal(); err != nil {
		return err
	}
	st, err := u.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.UserByEmail(ctx, email); err == nil {
		return store.ErrEmailTaken
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	hash, err := u.readNewPassword()
	if err != nil {
		return err
	}
	secret, step, err := u.setUpTOTP(email)
	if err != nil {
		return err
	}
	created, err := st.CreateUser(ctx, email, hash, role, secret, time.Now())
	if err != nil {
		return err
	}
	if err := st.UseTOTPStep(ctx, created.ID, step); err != nil {
		return err
	}
	fmt.Fprintf(u.Out, "\nCreated %s (%s). You can now log in to the dashboard.\n", email, role)
	return nil
}

func (u *UserCLI) List(ctx context.Context) error {
	st, err := u.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	users, err := st.Users(ctx)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Fprintln(u.Out, "No users yet. Add one with: bestbefore user add --email … --role admin")
		return nil
	}
	tw := tabwriter.NewWriter(u.Out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(tw, "EMAIL\tROLE\tTOTP\tCREATED")
	for _, usr := range users {
		totp := "set"
		if len(usr.TOTPSecret) == 0 {
			totp = "missing"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", usr.Email, usr.Role, totp, formatDate(usr.CreatedAt))
	}
	return tw.Flush()
}

func (u *UserCLI) SetRole(ctx context.Context, email, role string) error {
	if err := checkRole(role); err != nil {
		return err
	}
	return u.change(ctx, email, func(st *store.Store, usr *store.User) (string, error) {
		return "is now " + role, st.SetUserRole(ctx, usr.ID, role)
	})
}

func (u *UserCLI) ResetPassword(ctx context.Context, email string) error {
	if err := u.needTerminal(); err != nil {
		return err
	}
	return u.change(ctx, email, func(st *store.Store, usr *store.User) (string, error) {
		hash, err := u.readNewPassword()
		if err != nil {
			return "", err
		}
		return "has a new password", st.SetPasswordHash(ctx, usr.ID, hash)
	})
}

func (u *UserCLI) ResetTOTP(ctx context.Context, email string) error {
	if err := u.needTerminal(); err != nil {
		return err
	}
	return u.change(ctx, email, func(st *store.Store, usr *store.User) (string, error) {
		secret, step, err := u.setUpTOTP(email)
		if err != nil {
			return "", err
		}
		return "has a new authenticator; the old one no longer works", st.SetTOTP(ctx, usr.ID, secret, step)
	})
}

func (u *UserCLI) Delete(ctx context.Context, email string, confirmed bool) error {
	if !confirmed {
		if err := u.needTerminal(); err != nil {
			return fmt.Errorf("%w, or pass --yes", err)
		}
	}
	return u.change(ctx, email, func(st *store.Store, usr *store.User) (string, error) {
		if !confirmed {
			fmt.Fprintf(u.Out, "Type %s to delete this user: ", usr.Email)
			if !u.scan() || !strings.EqualFold(strings.TrimSpace(u.lines.Text()), usr.Email) {
				return "", errors.New("not confirmed; nothing was deleted")
			}
		}
		return "has been deleted", st.DeleteUser(ctx, usr.ID)
	})
}

// change applies fn to the user with this email and reports the outcome.
func (u *UserCLI) change(ctx context.Context, email string, fn func(*store.Store, *store.User) (string, error)) error {
	st, err := u.open(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	usr, err := st.UserByEmail(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no user with email %s", email)
	}
	if err != nil {
		return err
	}
	outcome, err := fn(st, usr)
	if err != nil {
		return err
	}
	fmt.Fprintf(u.Out, "%s %s. Their sessions have been ended.\n", usr.Email, outcome)
	return nil
}

func (u *UserCLI) open(ctx context.Context) (*store.Store, error) {
	if err := os.MkdirAll(u.Config.DataDir, 0o700); err != nil {
		return nil, err
	}
	return store.Open(ctx, filepath.Join(u.Config.DataDir, "bestbefore.db"))
}

func (u *UserCLI) needTerminal() error {
	if !term.IsTerminal(int(u.In.Fd())) {
		return errors.New("run this in a terminal")
	}
	return nil
}

func (u *UserCLI) scan() bool {
	if u.lines == nil {
		u.lines = bufio.NewScanner(u.In)
	}
	return u.lines.Scan()
}

// setUpTOTP shows a new secret and returns it once the user has entered a
// valid code from their app.
func (u *UserCLI) setUpTOTP(email string) ([]byte, uint64, error) {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return nil, 0, err
	}
	fmt.Fprintf(u.Out, "\nAdd this account to your authenticator app, by key:\n\n    %s\n\nor with this URI:\n\n    %s\n\n",
		auth.EncodeTOTPSecret(secret), auth.TOTPURI("Best Before", email, secret))
	for attempt := 1; ; attempt++ {
		fmt.Fprint(u.Out, "Code from the app: ")
		if !u.scan() {
			return nil, 0, errors.New("no code entered")
		}
		if step, ok := auth.VerifyTOTP(secret, strings.TrimSpace(u.lines.Text()), time.Now()); ok {
			return secret, step, nil
		}
		if attempt == 3 {
			return nil, 0, errors.New("three wrong codes; nothing was changed. Check the device's clock and start again")
		}
		fmt.Fprintln(u.Out, "That code does not match. Try again.")
	}
}

// readNewPassword asks twice, without echo, and returns the hash.
func (u *UserCLI) readNewPassword() (string, error) {
	fd := int(u.In.Fd())
	for {
		fmt.Fprint(u.Out, "Password: ")
		p1, err := term.ReadPassword(fd)
		fmt.Fprintln(u.Out)
		if err != nil {
			return "", err
		}
		if err := auth.CheckPasswordPolicy(string(p1)); err != nil {
			fmt.Fprintln(u.Out, err)
			continue
		}
		fmt.Fprint(u.Out, "Password again: ")
		p2, err := term.ReadPassword(fd)
		fmt.Fprintln(u.Out)
		if err != nil {
			return "", err
		}
		if string(p1) != string(p2) {
			fmt.Fprintln(u.Out, "The passwords do not match.")
			continue
		}
		return auth.HashPassword(string(p1))
	}
}

func checkRole(role string) error {
	if role != store.RoleAdmin && role != store.RoleUser {
		return fmt.Errorf("role must be %s or %s", store.RoleAdmin, store.RoleUser)
	}
	return nil
}
