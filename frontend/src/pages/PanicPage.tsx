import { useSearchParams } from "react-router-dom";
import { Link } from "react-router-dom";
import { PageTitle } from "../ui";

/* Landing page for the single-use panic link from the sign-in-detected
   email ("wasn't you? sign out everywhere and change your password").
   The backend has already done the work by the time the browser lands
   here — this page only reports the outcome. */
export default function PanicPage() {
  const [params] = useSearchParams();
  const status = params.get("status") ?? "invalid";

  const content =
    status === "done"
      ? {
          overline: "Security response",
          title: "You've been signed out everywhere",
          body: (
            <>
              <p className="mb-3 text-sm leading-relaxed text-ink-soft">
                Every session on your account has been revoked — including the one that
                triggered the alert email. Whoever was signed in is out.
              </p>
              <p className="mb-3 text-sm leading-relaxed text-ink-soft">
                We&rsquo;ve also emailed you a link to choose a new password. Use it — a
                sign-in you didn&rsquo;t recognize means the password should be considered
                compromised. Check your inbox (and spam) in the next few minutes.
              </p>
              <p className="text-sm leading-relaxed text-ink-soft">
                Didn&rsquo;t get the reset email? Request a new one from the forgot-password
                page.
              </p>
            </>
          ),
          link: { to: "/forgot-password", label: "Go to forgot password" },
        }
      : status === "busy"
        ? {
            overline: "Security response",
            title: "Almost — one moment",
            body: (
              <p className="text-sm leading-relaxed text-ink-soft">
                Another session operation was in flight when you clicked. The link is
                still valid — try it again in a few seconds.
              </p>
            ),
            link: null,
          }
        : status === "error"
          ? {
              overline: "Security response",
              title: "Something went wrong",
              body: (
                <p className="text-sm leading-relaxed text-ink-soft">
                  The sign-out could not be completed. Open your sessions page and revoke
                  everything manually, then change your password.
                </p>
              ),
              link: { to: "/login", label: "Sign in to review sessions" },
            }
          : {
              overline: "Security response",
              title: "This link no longer works",
              body: (
                <p className="text-sm leading-relaxed text-ink-soft">
                  Panic links are single-use and expire after 30 minutes — this one has
                  already been used or has timed out. If you still don&rsquo;t recognize
                  that sign-in, sign in and revoke your sessions manually, then change
                  your password.
                </p>
              ),
              link: { to: "/login", label: "Sign in to review sessions" },
            };

  return (
    <div className="flex min-h-screen items-center justify-center p-8">
      <div className="w-full max-w-md">
        <PageTitle overline={content.overline} title={content.title} aside={null} />
        <div className="rounded-sm border border-rule bg-paper-raised p-6">
          {content.body}
          {content.link && (
            <Link
              to={content.link.to}
              className="mt-6 inline-block rounded-sm border border-rule-strong bg-paper-raised px-4 py-2 text-sm font-medium text-ink transition-colors hover:bg-paper-sunken"
            >
              {content.link.label}
            </Link>
          )}
        </div>
      </div>
    </div>
  );
}
