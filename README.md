# AH13 Store — PWA starter

## Files
- `index.html`: bilingual RTL/LTR storefront, login, developer submissions, admin UI
- `style.css`, `app.js`: interface and logic
- `logo.jpg`, `icons/`: your supplied AH13 Store image as the PWA icon and loading logo
- `manifest.webmanifest`, `sw.js`: install and offline shell
- `database.sql`: Supabase tables, policies, roles and admin controls
- `config.js`: project settings

## Setup
1. Create a Supabase project. In SQL Editor run `database.sql`.
2. From Supabase project settings copy **Project URL** and **publishable/anon key** into `config.js`. Never use the service-role/secret key in browser code.
3. Set `developerWebsite` to your own URL in `config.js`.
4. Deploy the **contents** of this directory to Cloudflare Pages at the domain root, with no build command. HTTPS is required for PWA.
5. Register your own account, then run `update public.profiles set role='admin' where email='YOUR_ADMIN_EMAIL';` in Supabase SQL Editor.
6. In Supabase Auth settings configure allowed Site URL, redirect URLs and email confirmation.
7. Test signup, email confirmation, developer submission, admin approval and mobile installation.

## Important limitations
- This is a functioning starter, **not** a production-ready marketplace for 100,000 users or 20,000 apps.
- Submissions accept **HTTPS URLs and image URLs**, not ZIP uploads. Do not treat untrusted links as verified or safe.
- Admin can approve, hide, edit name/URL, delete apps and block profiles. Profile bans prevent submissions and admin operations, but do not automatically revoke existing Supabase Auth sessions. Configure additional enforcement for strict bans.
- Admin list and storefront currently load a maximum of 200 records. Add server-side pagination, indexed search, moderation, rate limiting, abuse protection, image uploads, monitoring, backups and accessibility review before large-scale deployment.
- PWA icon is a square crop of the image supplied by the user. For best icon legibility, a separate icon-only asset is recommended.
- The loading spinner is implemented in CSS and spins around/below the supplied logo. This does not require a GIF/video.
- No guaranteed zero-cost always-on database or 100k active-user capacity is implied.
