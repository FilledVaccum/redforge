# Dummy Values & Placeholder Tracker

Every placeholder in this codebase that needs a real value before production.

---

## Supabase

| Variable | File | Dummy Value | How to Get Real Value |
|---|---|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | `.env.local` | `https://DUMMY_PROJECT_ID.supabase.co` | Supabase Dashboard → Settings → API → Project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | `.env.local` | `DUMMY_SUPABASE_ANON_KEY_eyJ...` | Supabase Dashboard → Settings → API → anon public key |
| `SUPABASE_SERVICE_ROLE_KEY` | `.env.local` | `DUMMY_SUPABASE_SERVICE_ROLE_KEY` | Supabase Dashboard → Settings → API → service_role secret |

**Setup steps:**
1. Go to [supabase.com](https://supabase.com) → New Project
2. Copy URL + anon key + service role key to `.env.local`
3. Run the SQL migration: `supabase/migrations/001_initial_schema.sql` in the SQL Editor
4. Enable Email auth in Authentication → Providers

---

## Stripe

| Variable | File | Dummy Value | How to Get Real Value |
|---|---|---|---|
| `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` | `.env.local` | `pk_test_DUMMY_...` | Stripe Dashboard → Developers → API Keys → Publishable key |
| `STRIPE_SECRET_KEY` | `.env.local` | `sk_test_DUMMY_...` | Stripe Dashboard → Developers → API Keys → Secret key |
| `STRIPE_WEBHOOK_SECRET` | `.env.local` | `whsec_DUMMY_...` | Stripe Dashboard → Developers → Webhooks → Add endpoint → Signing secret |
| `STRIPE_PRICE_STARTER` | `.env.local` | `price_DUMMY_STARTER_4900` | Create product "Starter Audit" → $4,900 one-time → copy price ID |
| `STRIPE_PRICE_PROFESSIONAL` | `.env.local` | `price_DUMMY_PROFESSIONAL_12900` | Create product "Professional Audit" → $12,900 one-time → copy price ID |
| `STRIPE_PRICE_ENTERPRISE` | `.env.local` | `price_DUMMY_ENTERPRISE_CUSTOM` | Create product "Enterprise" → custom price → copy price ID |

**Setup steps:**
1. Go to [dashboard.stripe.com](https://dashboard.stripe.com) → Use test mode
2. Create 3 products (Starter $4,900 / Professional $12,900 / Enterprise placeholder)
3. Copy the API keys and price IDs to `.env.local`
4. Create a webhook endpoint: `https://your-domain.com/api/stripe/webhook`
5. Select events: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`
6. Copy the webhook signing secret to `.env.local`

---

## RedForge Scan Engine

| Variable | File | Dummy Value | How to Get Real Value |
|---|---|---|---|
| `REDFORGE_API_URL` | `.env.local` | `http://localhost:8000` | Deploy RedForge REST API (see `redforge/api/`) and use its URL |
| `REDFORGE_API_KEY` | `.env.local` | `DUMMY_REDFORGE_API_KEY` | Generate an API key for the scan service |

**Note:** The scan submission currently uses a mock/simulated response. When the RedForge REST API is deployed, wire `src/app/api/scans/route.ts` to hit the real endpoint.

---

## Formspree (Consulting Page)

| Variable | File | Dummy Value | How to Get Real Value |
|---|---|---|---|
| `YOUR_FORM_ID` | `website/consulting.html` | `YOUR_FORM_ID` in form action URL | Sign up at [formspree.io](https://formspree.io) → Create form → copy form ID |

---

## OAuth Providers (Optional)

| Provider | Where to Configure | How |
|---|---|---|
| GitHub OAuth | Supabase Dashboard → Auth → Providers → GitHub | Create GitHub OAuth app, paste client ID + secret |
| Google OAuth | Supabase Dashboard → Auth → Providers → Google | Create Google OAuth credentials, paste client ID + secret |

---

## Checklist Before Production

- [ ] Replace all `DUMMY_` values in `.env.local`
- [ ] Run `supabase/migrations/001_initial_schema.sql` in Supabase SQL Editor
- [ ] Create Stripe products and copy price IDs
- [ ] Set up Stripe webhook endpoint
- [ ] Replace `YOUR_FORM_ID` in consulting page
- [ ] Deploy RedForge REST API for real scan execution
- [ ] Configure custom domain
- [ ] Switch Stripe to live mode (replace `pk_test_` / `sk_test_` with `pk_live_` / `sk_live_`)
- [ ] Enable RLS policies are active in Supabase
- [ ] Set up monitoring / error tracking (Sentry recommended)
