import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import User from "../models/user.model.js";

export const configurePassport = () => {
  if (passport._finshieldConfigured) {
    return passport;
  }

  if ( !process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_CALLBACK_URL ) 
    {
    console.warn(
      "⚠️ Warning: Google OAuth environment variables are missing in process.env. Skipping Google Strategy configuration."
    );
    return passport;
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const googleId = profile.id;
          const email = profile.emails?.[0]?.value?.trim().toLowerCase();

          if (!email) {
            return done(new Error("Google account did not provide an email address"));
          }

          const name = profile.displayName?.trim() || email;

          let user = await User.findOne({ googleId });
          if (user) return done(null, user);

          user = await User.findOne({ email });
          if (user) {
            user.googleId = googleId;
            if (!user.name) user.name = name;
            // Google proved ownership of the email — clear any pending verification.
            user.isVerified = true;
            await user.save();
            return done(null, user);
          }

          try {
            user = await User.create({
              name,
              email,
              googleId,
              passwordHash: null,
              // Google already proved ownership of this email.
              isVerified: true,
            });
          } catch (createError) {
            // Lost a race with a concurrent registration or Google sign-in
            // on the same email — the unique index caught it. Re-fetch the
            // winner and link this Google account to it instead of failing.
            if (createError?.code !== 11000) {
              throw createError;
            }
            user = await User.findOne({ email });
            if (!user) {
              throw createError;
            }
            user.googleId = googleId;
            if (!user.name) user.name = name;
            user.isVerified = true;
            await user.save();
          }

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user._id || user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id).lean();
      done(null, user);
    } catch (error) {
      done(error);
    }
  });

  passport._finshieldConfigured = true;
  return passport;
};

// Export the passport instance directly as default
export default passport;