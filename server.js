'use strict';
// [FIX-DEPLOY-SQLITE] لازم يفضل أول سطر: بيضمن إن node:sqlite متاح
// قبل ما lib/db.js يتحمل، أيا كان أمر التشغيل اللي الاستضافة استخدمته.
require('./lib/ensure-sqlite');
// ElForma full-stack server — dependency-free (Node built-ins only).
// Serves: marketing/download pages, the gated admin panel, and the native app JSON API.
const http = require('http');
const path = require('path');
const fs = require('fs');
const { parseCookies, sendJson, sendText, serveStatic } = require('./lib/util');
const { enableCompression } = require('./lib/compress');
const authApi = require('./api/auth');
const stateApi = require('./api/state');
const nutritionEstimateApi = require('./api/nutrition-estimate');
const accountApi = require('./api/account');
const payApi = require('./api/pay');
const funnelApi = require('./api/funnel');
const verifyApi = require('./api/verify');
const adminApi = require('./api/admin');
const reviewsApi = require('./api/reviews');
const planApi = require('./api/plan');
const workoutApi = require('./api/workout');
const mobileApi = require('./api/mobile');
const ramadanApi = require('./api/ramadan').createHandler({
  healthOptions: userId => mobileApi.ramadanHealthOptions(userId),
  onChanged: userId => mobileApi.invalidateUserCaches(userId)
});
const communityApi = require('./api/community');
const friendChallengesApi = require('./api/friend-challenges');
const shareApi  = require('./api/share');
const auth = require('./lib/auth');
// [FIX-ADMIN-4] cfg was used by the /admin gate but never imported -> every
// request to /admin.html threw ReferenceError and returned 500 server_error.
const cfg = require('./lib/config');
const db = require('./lib/db');
// Catalog import/publication is an explicit administrator action, never startup work.

const commerce = require('./lib/commerce');
const { checkAccess } = auth;
const deviceClock=require('./lib/device-time');
const userTimezones=require('./lib/user-timezone');

const PORT = process.env.PORT || 8000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.EF_DATA_DIR || path.join(ROOT, 'data');
const lifecycle = { draining: false };
let buildCommit = null;
try {
  const candidate = JSON.parse(fs.readFileSync(path.join(ROOT, 'build-info.json'), 'utf8')).commit;
  if (/^[a-f0-9]{40,64}$/.test(candidate || '')) buildCommit = candidate;
} catch (_) { /* Local development has no release metadata. */ }

const metrics = require('./lib/metrics');
require('./lib/cluster-metrics').register(() => {
        const extra = {};
        try { const p = require('./lib/engine-pool').stats(); extra.ef_engine_busy = p.busy; extra.ef_engine_queued = p.queued; extra.ef_engine_pool_size = p.poolSize; } catch (_) {}
        try { const m = require('./lib/mailer').stats; extra.ef_mail_attempted_total = m.attempted; extra.ef_mail_delivered_total = m.delivered; extra.ef_mail_failed_total = m.failed; extra.ef_mail_retried_total = m.retried; } catch (_) {}
        try { const c = require('./lib/cache-redis').nutritionCache.stats(); extra.ef_nutrition_cache_size = c.size; extra.ef_nutrition_cache_hits_total = c.hits; extra.ef_nutrition_cache_misses_total = c.misses; } catch (_) {}
        extra.ef_draining = lifecycle.draining ? 1 : 0;
  return metrics.render(extra);
});

function clientIp(req) {
  // Only trust X-Forwarded-For behind a known proxy (EF_TRUST_PROXY=1),
  // otherwise clients could spoof it to bypass rate limits.
  if (process.env.EF_TRUST_PROXY === '1') {
    const xf = req.headers['x-forwarded-for'];
    if (xf) return String(xf).split(',')[0].trim();
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://www.paypal.com https://www.paypalobjects.com https://accept.paymob.com https://cdn.jsdelivr.net https://accounts.google.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' https://accept.paymob.com https://www.paypal.com https://api-m.paypal.com https://accounts.google.com",
    "frame-src 'self' https://accept.paymob.com https://www.paypal.com https://www.sandbox.paypal.com https://accounts.google.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'"
  ].join('; '));
  if (process.env.EF_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

/* [FIX M12 — مفيش لوج منظم ولا معرف للطلب]
   المشكلة المثبتة: كل اللي كان موجود هو console.error('[server]', err) وبس.
   لما يوصلك شكوى "الخطة مافتحتش الساعة 4"، مافيش طريقة تربط الشكوى
   دي بسطر لوج معين، ولا تعرف الطلب أخد قد إيه، ولا رجع كود إيه.

   الحل هنا متعمد إنه بسيط ومن غير مكتبات (المشروع zero-dependency):
     • كل طلب له requestId عشوائي بيرجع في هيدر X-Request-Id.
     • سطر واحد JSON لكل طلب API: المسار، الطريقة، الكود، المدة بالملي‌ثانية.
     • الأخطاء بتطلع بنفس الـ requestId، فالمستخدم يقدر يبعتلك الرقم وتلاقيه.

   مابنسجلش أبدا: الكوكيز، التوكنات، الباودي، الإيميل، أو الـ query string كاملة.
   الـ IP بيتقطع لآخر octet (خصوصية) وبيقفل خالص بـ EF_LOG_IP=0. */
const LOG_REQUESTS = process.env.EF_LOG_REQUESTS !== '0';
const LOG_IP = process.env.EF_LOG_IP !== '0';

function newRequestId() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36).slice(-4);
}

function maskIp(ip) {
  if (!LOG_IP || !ip) return null;
  if (ip.indexOf('.') > -1) return ip.split('.').slice(0, 3).join('.') + '.x';
  return ip.split(':').slice(0, 3).join(':') + ':x';   // IPv6
}

function logLine(fields) {
  try { console.log(JSON.stringify(fields)); }
  catch (_) { console.log('[log] unserialisable entry'); }
}

async function handleRequest(req, res) {
  const ip = clientIp(req);
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  securityHeaders(res);
  if (lifecycle.draining) { try { res.setHeader('Connection', 'close'); } catch (_) {} }

  // [FIX M12] معرف الطلب: بيتحط على الرد قبل أي حاجة، وبيتحط على req
  // عشان أي معالج جوا يقدر يستخدمه لو احتاج.
  const requestId = newRequestId();
  req.requestId = requestId;
  const startedAt = process.hrtime.bigint();
  try { res.setHeader('X-Request-Id', requestId); } catch (_) { /* headers already sent */ }

  res.on('finish', function () {
    try { metrics.observe(req.method, pathname, res.statusCode, Number(process.hrtime.bigint() - startedAt) / 1e6); } catch (_) {}
  });

  if (LOG_REQUESTS && pathname.startsWith('/api/')) {
    res.on('finish', function () {
      const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
      logLine({
        t: new Date().toISOString(),
        lvl: res.statusCode >= 500 ? 'error' : (res.statusCode >= 400 ? 'warn' : 'info'),
        rid: requestId,
        method: req.method,
        path: pathname,               // المسار بس — مفيش query string
        status: res.statusCode,
        ms: Math.round(ms * 10) / 10,
        ip: maskIp(ip),
      });
    });
  }

  try {
    // ---------- API ----------
    // Serve uploaded images (admin-uploaded announcement images etc.)
    if (pathname.startsWith('/uploads/images/')) {
      const fname = path.basename(pathname);
      if (!/^img_[\w.-]+$/.test(fname)) return sendJson(res, 400, { error: 'bad_path' });
      const fpath = path.join(DATA_DIR, 'uploads', 'images', fname);
      if (!fs.existsSync(fpath)) return sendJson(res, 404, { error: 'not_found' });
      const ext = path.extname(fname).toLowerCase();
      const mime = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp' }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'public, max-age=86400' });
      // [ITEM-13] التيار بلا معالج خطأ كان يحوّل حذف ملف متزامن مع طلبه
      // (الأدمن يحذف صور إعلانات من اللوحة) إلى استثناء غير ملتقط يوقع العملية
      // كلها. النمط نفسه المعتمد في lib/util.js: سجّل وادمّر الرد، والعملية حية.
      const imgStream = fs.createReadStream(fpath);
      imgStream.on('error', (e) => {
        console.error('[stream] uploaded image read failed:', fpath, e && e.message);
        try { res.destroy(); } catch (_) {}
      });
      imgStream.pipe(res);
      return;
    }

    if (pathname.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
      if (!['GET','HEAD','OPTIONS'].includes(req.method)) {
        const origin = req.headers.origin;
        const fetchSite = req.headers['sec-fetch-site'];
        let foreign = fetchSite === 'cross-site';
        if (origin) {
          try {
            const incoming = new URL(origin);
            const expected = new URL(require('./lib/config').APP.base_url);
            foreign = incoming.origin !== expected.origin;
            // The bound local origin is accepted only outside production.
            if (require('./lib/config').APP.env !== 'production' && incoming.host === req.headers.host) foreign = false;
          } catch (_) { foreign = true; }
        }
        if (foreign) return sendJson(res,403,{error:'request_origin_rejected'});
      }
      // ردود الـ API بتتضغط لو العميل بيقبل gzip: أكبر رد (تاريخ التمرين)
      // بينزل من مئات الكيلوبايت لعشرات، وده أكبر فرق في سرعة الشاشة على شبكة موبايل.
      enableCompression(req, res);
      if (req.method === 'POST' && ['/api/pay/manual','/api/pay/paymob','/api/pay/paypal/create'].includes(pathname) && req.headers['idempotency-key']) {
        if (await require('./lib/idempotency').begin(req,res,parseCookies(req).ef_session || '',8*1024*1024)) return;
      }
      // [B18-IDEMPOTENCY] Retried mobile writes carrying the same
      // Idempotency-Key are executed once and replayed afterwards.
      if (pathname.startsWith('/api/mobile/') && req.headers['idempotency-key']) {
        const sessionValue = parseCookies(req).ef_session || '';
        if (await require('./lib/idempotency').begin(req, res, sessionValue)) return;
      }
      // [B18-OPS] liveness = process is up; readiness = can serve traffic now.
      // Load balancers must route on /api/health/ready so a draining or
      // DB-less instance stops receiving users before it is restarted.
      if (pathname === '/api/health/live') return sendJson(res, 200, { ok: true });
      if (pathname === '/api/health/ready') {
        if (lifecycle.draining) return sendJson(res, 503, { ok: false, reason: 'draining' });
        try { db.db.prepare('SELECT 1').get(); }
        catch (_) { return sendJson(res, 503, { ok: false, reason: 'database_unavailable' }); }
        return sendJson(res, 200, { ok: true, uptimeSec: Math.round(process.uptime()), buildCommit });
      }
      if (pathname === '/api/metrics') {
        if (!metrics.authorized(req)) return sendJson(res, 404, { error: 'not_found' });
        let rendered;
        try { rendered = await require('./lib/cluster-metrics').collect(); }
        catch (_) { return sendJson(res, 503, { error: 'metrics_temporarily_unavailable' }); }
        res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(rendered);
      }
      if (pathname === '/api/health') return sendJson(res, 200, { ok: true, ts: Date.now(), storage: (function(){ try { return require('./lib/db').storage; } catch (_) { return null; } })() });
      if (req.method === 'POST' && pathname === '/api/nutrition-estimate') return void (await nutritionEstimateApi.post(req, res, ip));

      if (req.method === 'GET' && pathname === '/api/auth/config') {
        res.setHeader('Cache-Control','no-store');
        const clientId=process.env.GOOGLE_CLIENT_ID || '';
        return void sendJson(res,200,{google_client_id:/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId)?clientId:null});
      }
      if (req.method === 'POST' && pathname === '/api/auth/signup') return void (await authApi.signup(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/login') return void (await authApi.login(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/google') return void (await authApi.googleAuth(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/logout') return void (await authApi.logout(req, res));
      if (req.method === 'GET' && pathname === '/api/auth/me') return void (await authApi.me(req, res));

      if (req.method === 'GET' && pathname === '/api/state') return void (await stateApi.getAll(req, res));
      if (req.method === 'PUT' && pathname === '/api/state') return void (await stateApi.put(req, res));

      if (req.method === 'GET' && pathname === '/api/account/export') return void (await accountApi.exportData(req, res));
      if (req.method === 'POST' && pathname === '/api/account/delete') return void (await accountApi.deleteAccount(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/account/profile') return void (await accountApi.updateProfile(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/account/password') return void (await accountApi.changePassword(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/account/logout-all') return void (await accountApi.logoutAllDevices(req, res, ip));

      // ---- Commerce: plans, coupons, checkout, payments ----
      if (req.method === 'POST' && pathname === '/api/funnel/event') return void (await funnelApi.postEvent(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/plans') return void (await payApi.plans(req, res));
      if (req.method === 'GET' && pathname === '/api/content') return void (await payApi.content(req, res));
      if (req.method === 'GET' && pathname === '/api/pay/methods') return void (await payApi.methods(req, res));
      if (req.method === 'GET' && pathname === '/api/pay/mine') return void (await payApi.mine(req, res));
      if (req.method === 'POST' && pathname === '/api/coupon/check') return void (await payApi.couponCheck(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/pay/manual') return void (await payApi.manual(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/pay/paymob') return void (await payApi.paymob(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/pay/google/tag') return void (await payApi.googleTag(req, res));
      if (req.method === 'POST' && pathname === '/api/pay/google/verify') return void (await payApi.googleVerify(req, res));
      if (req.method === 'POST' && pathname === '/api/pay/google/rtdn') return void (await payApi.googleRtdn(req, res));
      if (req.method === 'POST' && pathname === '/api/pay/paymob/webhook') return void (await payApi.paymobWebhook(req, res));
      if (req.method === 'POST' && pathname === '/api/pay/paypal/create') return void (await payApi.paypalCreate(req, res));
      if (req.method === 'POST' && pathname === '/api/pay/paypal/recover') return void (await payApi.paypalRecover(req,res));
      if (req.method === 'POST' && pathname === '/api/pay/paypal/capture') return void (await payApi.paypalCapture(req, res));

      // ---- Email verification + password reset ----
      if (req.method === 'POST' && pathname === '/api/auth/verify/send') return void (await verifyApi.sendVerification(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/verify') return void (await verifyApi.verify(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/forgot') return void (await verifyApi.forgot(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/reset') return void (await verifyApi.reset(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/phone/otp/send') return void (await verifyApi.sendPhoneOtp(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/auth/phone/otp/verify') return void (await verifyApi.verifyPhoneOtp(req, res, ip));

      // ---- Reviews (public read, auth write, admin moderation) ----
      if (req.method === 'GET' && pathname === '/api/reviews') return void (await reviewsApi.list(req, res));
      if (req.method === 'GET' && pathname === '/api/reviews/mine') return void (await reviewsApi.mine(req, res));
      if (req.method === 'POST' && pathname === '/api/reviews') return void (await reviewsApi.submit(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/reviews/pending') return void (await reviewsApi.pending(req, res));
      if (req.method === 'POST' && pathname === '/api/reviews/moderate') return void (await reviewsApi.moderate(req, res, ip));

      // Server-side plan computation (premium logic never leaves the server).
      //
      // These routes are intentionally NOT behind a hard access gate. Each
      // handler already checks the subscription itself (api/plan.js and
      // api/workout.js call subActive() and fall back to gatePreview()), which
      // is what powers the free teaser the paywall UI expects. Rejecting the
      // request up here with a 401/402 would delete that preview for every
      // logged-out visitor and every free account.
      if (req.method === 'POST' && pathname === '/api/plan/compute') return void (await planApi.compute(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/plan/targets') return void (await planApi.targets(req, res));
      if (req.method === 'POST' && pathname === '/api/workout/compute') return void (await workoutApi.compute(req, res, ip));

      // Native mobile persistence (no browser localStorage).
      if (pathname === '/api/mobile/community' || pathname.startsWith('/api/mobile/community/') || pathname.startsWith('/api/admin/community/')) return void (await communityApi.handle(req, res, pathname, ip));
      if (pathname === '/api/mobile/friend-challenges' || pathname.startsWith('/api/mobile/friend-challenges/')) return void (await friendChallengesApi.handle(req, res, pathname));
      if (req.method === 'GET' && pathname === '/api/mobile/announcements/watch') return void (await mobileApi.watchAnnouncements(req, res));
      if (pathname === '/api/mobile/ramadan') return void (await ramadanApi.handle(req,res,pathname));
      if (req.method === 'GET' && pathname === '/api/mobile/account') return void (await mobileApi.accountSnapshot(req,res));
      if (req.method === 'GET' && pathname === '/api/mobile/subscription') return void (await mobileApi.subscriptionSnapshot(req,res));
      if (req.method === 'POST' && pathname === '/api/mobile/subscription/auto-renew') return void (await mobileApi.setAutoRenew(req,res));
      if (req.method === 'GET' && pathname === '/api/mobile/bootstrap') return void (await mobileApi.bootstrap(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/modules') return void (await mobileApi.modules(req, res));
      // التاريخ بيتقرا على دفعات مش مرة واحدة
      if (req.method === 'GET' && pathname === '/api/mobile/history') return void (await mobileApi.history(req, res));
      // Public kill-switch for bad releases. Deliberately NOT behind auth: a
      // blocked build must be able to ask before it can even log in.
      if (req.method === 'GET' && pathname === '/api/app/version') return void (await mobileApi.appVersion(req, res));
      // المتدرب بيبلغ إن فيديو مش شغال
      if (req.method === 'POST' && pathname === '/api/app/video-report') return void (await mobileApi.reportVideo(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/profile') return void (await mobileApi.saveProfile(req, res));
      if (req.method === 'DELETE' && pathname === '/api/mobile/data') return void (await mobileApi.deleteMobileData(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/diet/recommend') return void (await mobileApi.dietRecommend(req, res));
      // [FIX-CHAT-EXIT] تجهيز الخطط التقيل بيحصل هنا — صفحة التحليل بتنده عليه
      // وهي شغالة بواجهة الانتظار المصممة، بدل ما يحبس زر الشات المستخدم.
      if (req.method === 'POST' && pathname === '/api/mobile/plans/prepare') return void (await mobileApi.preparePlansNow(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/workout-plan') return void (await mobileApi.activatePlan(req, res));
      // v37 «صمم جدولك بنفسك»
      if (req.method === 'GET' && pathname === '/api/mobile/custom-plan/catalog') return void (await mobileApi.customPlanCatalog(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/custom-plan') return void (await mobileApi.customPlanGet(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/custom-plan') return void (await mobileApi.customPlanSave(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/custom-plan/switch') return void (await mobileApi.customPlanSwitch(req, res));
      if (req.method === 'DELETE' && pathname === '/api/mobile/custom-plan') return void (await mobileApi.customPlanDelete(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/session/start') return void (await mobileApi.startSession(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/session/set') return void (await mobileApi.saveSet(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/session/finish') return void (await mobileApi.finishSession(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/nutrition') return void (await mobileApi.saveNutrition(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/weight') return void (await mobileApi.saveWeight(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/measurement') return void (await mobileApi.saveMeasurement(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/foods') return void (await mobileApi.foodSearch(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/food-preferences') return void (await mobileApi.foodPreferences(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/food-preference') return void (await mobileApi.saveFoodPreference(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/exercise-history') return void (await mobileApi.exerciseHistory(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/exercise-alternatives') return void (await mobileApi.exerciseAlternatives(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/workout-history') return void (await mobileApi.workoutHistory(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/progress-story') return void (await mobileApi.progressStory(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/progress-story/ack') return void (await mobileApi.acknowledgeProgressMoments(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/grocery-list') return void (await mobileApi.groceryList(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/nutrition-plan') return void (await mobileApi.nutritionPlan(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/client-event') return void (await mobileApi.clientEvent(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/smart-coach') return void (await mobileApi.smartCoachGet(req, res));
      if (req.method === 'PUT' && pathname === '/api/mobile/smart-coach') return void (await mobileApi.smartCoachSet(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/nutrition/override') return void (await mobileApi.saveMealOverride(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/nutrition/overrides') return void (await mobileApi.getMealOverrides(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/trial/start') return void (await mobileApi.startTrial(req, res, ip));
      // رد المتدرب على سؤال الالتزام لما مايكونش مسجل داتا.
      if (req.method === 'POST' && pathname === '/api/mobile/checkin') return void (await mobileApi.checkinSubmit(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/notifications') return void (await mobileApi.getNotifications(req, res));
      // ---- Push وإعدادات التطبيق الحية ----
      // تسجيل توكن الجهاز هو اللي بيخلي إشعار الأدمن يوصل والتطبيق مقفول.
      if (req.method === 'POST' && pathname === '/api/mobile/device/register') return void (await mobileApi.registerDevice(req, res));
      if (req.method === 'POST' && pathname === '/api/mobile/device/unregister') return void (await mobileApi.unregisterDevice(req, res));
      if (req.method === 'GET' && pathname === '/api/mobile/app-config') return void (await mobileApi.mobileAppConfig(req, res));

      // ---- Admin payment review ----
      if (req.method === 'GET' && pathname === '/api/admin/whoami') return void (await adminApi.whoami(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/setup/verify') return void (await adminApi.setupVerify(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/payments') return void (await adminApi.payments(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/payment/approve') return void (await adminApi.approve(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/payment/reject') return void (await adminApi.reject(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/receipt') return void (await adminApi.receipt(req, res));
      if (req.method === 'GET' && pathname === '/api/admin/stats') return void (await adminApi.stats(req, res));
      if (req.method === 'GET' && pathname === '/api/admin/funnel') return void (await adminApi.funnel(req, res));
      // [OPS] مؤشرات تشغيل حية للأدمن — بدون أي خدمة مراقبة خارجية (قراءة فقط).
      // بيجاوب على: هل الـ worker pool متخنق؟ الكاش بيضرب كويس؟ الذاكرة فين؟
      // الأبتايم كام؟ — وكل ده من السيرفر نفسه، ببوابة الأدمن العادية.
      if (req.method === 'GET' && pathname === '/api/admin/ops') {
        const opsUser = auth.currentUser(parseCookies(req));
        if (!opsUser || !cfg.isAdminEmail(opsUser.email)) return sendJson(res, 403, { error: 'forbidden' });
        return sendJson(res, 200, {
          ok: true,
          uptimeSec: Math.round(process.uptime()),
          memoryMb: Math.round(process.memoryUsage().rss / 1048576),
          node: process.version,
          db: (function(){ try { return require('./lib/db').storage.engine; } catch (_) { return null; } })(),
          enginePool: require('./lib/engine-pool').stats(),
          bootstrapCache: mobileApi.bootstrapCacheStats(),
        });
      }
      if (req.method === 'GET' && pathname === '/api/admin/users') return void (await adminApi.users(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/user/subscription') return void (await adminApi.setUserSubscription(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/user/delete') return void (await adminApi.deleteUser(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/users/bulk') return void (await adminApi.bulkUsers(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/coupons') return void (await adminApi.coupons(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/coupon/upsert') return void (await adminApi.couponUpsert(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/coupon/toggle') return void (await adminApi.couponToggle(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/coupon/delete') return void (await adminApi.couponDelete(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/announcements') return void (await adminApi.announcementsGet(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/announcements') return void (await adminApi.announcementsSave(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/announcements/preview') return void (await adminApi.announcementsPreview(req, res));
      if (req.method === 'GET' && pathname === '/api/admin/referrals') return void (await adminApi.referrals(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/referral/create') return void (await adminApi.referralCreate(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/pricing') return void (await adminApi.pricingGet(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/pricing') return void (await adminApi.pricingSave(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/videos') return void (await adminApi.videos(req, res));
      if (req.method === 'GET' && pathname === '/api/admin/exercises') return void (await adminApi.exercises(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/exercise/save') return void (await adminApi.exerciseSave(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/exercise/remove') return void (await adminApi.exerciseRemove(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/video/set') return void (await adminApi.videoSet(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/video/remove') return void (await adminApi.videoRemove(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/video/reset') return void (await adminApi.videoReset(req, res, ip));
      // طابور بلاغات الفيديو
      if (req.method === 'GET' && pathname === '/api/admin/video-reports') return void (await adminApi.videoReports(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/video-report/resolve') return void (await adminApi.videoReportResolve(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/content') return void (await adminApi.contentGet(req, res));
      if (req.method === 'GET' && pathname === '/api/admin/promo') return void (await adminApi.promoList(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/promo') return void (await adminApi.promoAction(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/content') return void (await adminApi.contentSave(req, res, ip));
      if (req.method === 'GET' && pathname === '/api/admin/gateways') return void (await adminApi.gatewaysGet(req,res));
      if (req.method === 'POST' && pathname === '/api/admin/gateways') return void (await adminApi.gatewaysSave(req,res,ip));
      if (req.method === 'GET' && pathname === '/api/admin/payment-methods') return void (await adminApi.paymentMethodsGet(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/payment-methods') return void (await adminApi.paymentMethodsSave(req, res, ip));

      // ---- Admin: custom subscription plans ----
      if (req.method === 'GET'  && pathname === '/api/admin/plans')       return void (await adminApi.planList(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/plan/add')    return void (await adminApi.planAdd(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/plan/delete') return void (await adminApi.planDelete(req, res, ip));

      // ---- Promo redemption (signed-in users) ----
      if (req.method === 'POST' && pathname === '/api/promo/redeem') {
        const gate = checkAccess(parseCookies(req));
        if (gate) return sendJson(res, gate.status, { error: gate.error });
        const me = auth.currentUser(parseCookies(req));
        const body = await require('./lib/util').readJsonBody(req);
        const out = commerce.redeemPromo(me.id, body && body.code);
        return sendJson(res, out.ok ? 200 : 400, out);
      }

      // ---- Feature Flags ----
      // Reads the same feature_flags table the admin screen writes to, so the
      // public endpoint and the admin toggle can never disagree.
      if (req.method === 'GET' && pathname === '/api/features') {
        const rows = db.getAllFeatureFlags();
        const flags = { ai_nutritionist: true, ai_coach: true };
        for (const row of rows) flags[row.key] = row.value === '1';
        return sendJson(res, 200, { ok: true, features: flags });
      }
      if (req.method === 'GET' && pathname === '/api/admin/features') return void (await adminApi.featuresGet(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/features') return void (await adminApi.featuresSave(req, res, ip));
      if (req.method === 'GET'  && pathname === '/api/admin/notifications') return void (await adminApi.notificationsGet(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/notifications/send') return void (await adminApi.notificationsSend(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/notifications/delete') return void (await adminApi.notificationDelete(req, res, ip));
      if (req.method === 'POST' && pathname === '/api/admin/upload') return void (await adminApi.uploadImage(req, res, ip));
      // حالة الـPush الحقيقية (FCM مضبوط؟ كام جهاز مستعد يستقبل؟)
      if (req.method === 'GET' && pathname === '/api/admin/push/status') return void (await adminApi.pushStatus(req, res));
      // إعدادات التطبيق: الصيانة، بوابة الإصدار، المفاتيح العامة
      if (req.method === 'GET' && pathname === '/api/admin/app-config') return void (await adminApi.appConfigGet(req, res));
      if (req.method === 'POST' && pathname === '/api/admin/app-config') return void (await adminApi.appConfigSave(req, res, ip));
      // سجل العمليات من جدول audit_log
      if (req.method === 'GET' && pathname === '/api/admin/audit') return void (await adminApi.auditLog(req, res));

      // ---- Share plan ----
      // Creating a share link requires a signed-in user (it reads THEIR plan).
      // Reading one by token is deliberately public -- that is the point.
      if (req.method === 'POST' && pathname === '/api/share/plan') {
        const gate = checkAccess(parseCookies(req));
        if (gate) return sendJson(res, gate.status, { error: gate.error });
        return void (await shareApi.createShare(req, res));
      }
      if (req.method === 'GET'  && pathname.startsWith('/api/share/')) {
        const token = pathname.slice('/api/share/'.length);
        return void (await shareApi.getShare(req, res, token));
      }

      
    return sendJson(res, 404, { error: 'not_found' });
    }

    if (req.method === 'GET' && pathname === '/.well-known/assetlinks.json') {
      const fingerprints = String(process.env.EF_ANDROID_CERT_SHA256 || '').split(',').map(function(value){ return value.trim(); }).filter(Boolean);
      if (!fingerprints.length) return sendJson(res, 404, { error: 'not_configured' });
      res.writeHead(200, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'public, max-age=3600'});
      return res.end(JSON.stringify([{
        relation: ['delegate_permission/common.handle_all_urls'],
        target: {namespace:'android_app',package_name:'com.elforma.elforma',sha256_cert_fingerprints:fingerprints}
      }]));
    }

    // ---------- Private challenge invite ----------
    if (req.method === 'GET' && pathname.startsWith('/challenge/join/')) {
      const code = pathname.slice('/challenge/join/'.length).toUpperCase();
      if (!/^[A-Z0-9-]{6,20}$/.test(code)) return sendText(res, 404, 'الدعوة غير متاحة');
      const safeCode = code.replace(/[^A-Z0-9-]/g, '');
      const html = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>دعوة لتحدي</title>' +
        '<style>body{margin:0;background:#f7f9f1;color:#173d30;font-family:system-ui;display:grid;min-height:100vh;place-items:center;padding:20px}.card{max-width:430px;background:white;border:1px solid #dbe4da;border-radius:26px;padding:30px;text-align:center;box-shadow:0 18px 50px #173d301a}h1{margin:0 0 10px}p{line-height:1.8;color:#5f6f68}.code{font-size:25px;font-weight:800;letter-spacing:2px;margin:20px 0}.btn{display:block;background:#087443;color:white;text-decoration:none;padding:14px;border-radius:14px;font-weight:800}</style></head><body>' +
        '<main class="card"><h1>دعوة لتحدي في الفورمة</h1><p>افتح التطبيق وشاهد تفاصيل التحدي قبل الانضمام</p>' +
        '<div class="code">' + safeCode + '</div><a class="btn" href="elforma://friend-challenge/' + safeCode + '">فتح في التطبيق</a>' +
        '<p>يمكنك ايضا كتابة الكود من شاشة تحديات الاصحاب</p></main></body></html>';
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});
      return res.end(html);
    }

    // The app/ tree remains private server-engine source, never a browser UI.
    // Decode/normalize like serveStatic before checking protected static paths;
    // encoded segments must not bypass either the app retirement or admin gate.
    let staticPathname;
    try { staticPathname = path.posix.normalize(decodeURIComponent(pathname)); }
    catch (_) { return sendText(res, 400, 'Bad path'); }
    if (staticPathname === '/app' || staticPathname.startsWith('/app/')) {
      res.setHeader('Cache-Control', 'no-store');
      if (req.method === 'GET' || req.method === 'HEAD') {
        res.writeHead(302, { Location: '/' }); // Existing download-only landing page.
        return res.end();
      }
      return sendJson(res, 410, { error: 'app_only', downloadUrl: 'https://elforma.fit/#download' });
    }

    // Older public checkout pages linked to the administration form. Only an
    // exact local checkout target may migrate to the customer sign-in route.
    if ((staticPathname === '/login.html' || staticPathname === '/login') &&
        (req.method === 'GET' || req.method === 'HEAD')) {
      const legacyCheckout = /^\/?checkout(?:\.html)?\?plan=([A-Za-z0-9_-]{1,60})$/.exec(url.searchParams.get('next') || '');
      if (legacyCheckout) {
        res.writeHead(302, { Location: '/signin?next=' + encodeURIComponent('/checkout?plan=' + legacyCheckout[1]), 'Cache-Control': 'no-store' });
        return res.end();
      }
    }

    // ---------- Public share links ----------
    // /share/<token> serves one static page; the page then fetches
    // /api/share/<token> for the payload. Keeps the token out of the HTML.
    if (pathname === '/share' || pathname.startsWith('/share/')) {
      if (serveStatic(res, PUBLIC_DIR, '/share.html', req)) return;
    }

    // ---------- Admin panel (auth + allowlist gated) ----------
    // [FIX-ADMIN-3] قبل كده admin.html كان ملف ستاتيك مفتوح للكل: أي حد يفتح
    // /admin.html يشوف اللوحة كاملة من غير تسجيل دخول (البيانات بس كانت فارغة).
    // دلوقتي البوابة على السيرفر: مفيش جلسة => تحويل للوجين، حساب مش أدمن => 403.
    // وكمان /admin و /login بقوا مسارات شغالة (كانو 404 قبل كده).
    if (staticPathname === '/admin' || staticPathname === '/admin/' || staticPathname === '/admin.html'
        ) {   // [UNIFIED-ADMIN] لوحة واحدة بس: /admin -> public/admin.html
      // [FIX-ADMIN-6] أي غلطة جوا بوابة الأدمن كانت بتطلع للمستخدم
      // server_error مع requestId. دلوقتي أوفر حالة: تحويل للوجين.
      let adminUser = null;
      try {
        adminUser = auth.currentUser(parseCookies(req));
      } catch (adminGateErr) {
        res.writeHead(302, { Location: '/login.html?next=' + encodeURIComponent('/admin.html') });
        return res.end();
      }
      if (!adminUser) {
        res.writeHead(302, { Location: '/login.html?next=' + encodeURIComponent('/admin.html') });
        return res.end();
      }
      if (!adminUser.verified || !cfg.isAdminEmail(adminUser.email)) {
        const adminEmailCandidate = cfg.isAdminEmail(adminUser.email);
        const safeEmail = String(adminUser.email || '').replace(/[<>&"]/g, '');
        const heading = adminEmailCandidate
          ? 'حساب الأدمن محتاج تأكيد البريد'
          : 'الحساب ده مش مسؤول النظام';
        const message = adminEmailCandidate
          ? 'إيميل الأدمن صحيح. لن نحولك للموقع؛ أكد البريد ثم سجل الدخول مرة ثانية.'
          : 'أنت داخل بحساب غير موجود في قائمة مسؤولي النظام.';
        const notAdminHtml = [
          '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">',
          '<meta name="viewport" content="width=device-width,initial-scale=1">',
          '<title>لوحة التحكم · ElForma</title>',
          '<style>',
          '*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;',
          'background:radial-gradient(1200px 600px at 50% -10%,#10281f 0%,#0a0b0f 60%);color:#e2e8f0;',
          "font-family:system-ui,'Segoe UI',Tahoma,sans-serif;padding:24px}",
          '.card{max-width:520px;width:100%;background:#12141c;border:1px solid #1e2030;border-radius:18px;padding:32px 28px;text-align:center;',
          'box-shadow:0 24px 60px rgba(0,0,0,.45)}',
          '.lock{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;',
          'background:rgba(16,185,129,.12);border:1px solid rgba(16,185,129,.35);font-size:18px;font-weight:900;color:#34d399}',
          'h1{font-size:20px;margin:0 0 10px}p{color:#94a3b8;font-size:14px;line-height:1.9;margin:0 0 6px}',
          '.em{color:#e2e8f0;font-weight:700}',
          '.row{display:flex;gap:10px;justify-content:center;margin-top:22px;flex-wrap:wrap}',
          'a.btn{background:#10b981;color:#04140e;padding:11px 20px;border-radius:10px;font-weight:800;text-decoration:none}',
          'a.gh{background:#1a1c27;color:#e2e8f0}',
          '.hint{margin-top:16px;font-size:12px;color:#64748b}',
          '</style></head><body><div class="card">',
          '<div class="lock">ADMIN</div>',
          '<h1>' + heading + '</h1>',
          '<p>الحساب الحالي: <span class="em">' + safeEmail + '</span></p>',
          '<p>' + message + '</p>',
          '<div class="row"><a class="btn" href="/login.html?next=%2Fadmin.html">تسجيل الدخول من جديد</a>',
          '<a class="btn gh" href="/">الصفحة الرئيسية</a></div>',
          '<div class="hint">هذه الصفحة متاحة لحسابات الإدارة المعتمدة فقط</div>',
          '</div></body></html>'
        ].join('');
        res.writeHead(403, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(notAdminHtml);
      }
      const adminFile = '/admin.html';
      if (serveStatic(res, PUBLIC_DIR, adminFile, req)) return;
      return sendText(res, 404, 'Not found');
    }

    if (/^\/(?:signin|signup|account|checkout|verify-email|reset|login)(?:\.html)?\/?$/.test(staticPathname)) {
      res.setHeader('Cache-Control','no-store');
      res.setHeader('Referrer-Policy','no-referrer');
    }
    // Customer routes are distinct from the administration login page.
    const customerPage = /^\/(signin|signup|account|checkout|verify-email|reset)(?:\.html)?\/?$/.exec(staticPathname);
    if (customerPage && (req.method === 'GET' || req.method === 'HEAD')) {
      if (serveStatic(res, PUBLIC_DIR, '/' + customerPage[1] + '.html', req)) return;
    }
    // ---------- Marketing / static public ----------
    if (pathname === '/') { if (serveStatic(res, PUBLIC_DIR, '/index.html', req)) return; }
    // [FIX] مسارات بدون امتداد .html عشان أي تحويل لـ/login أو /signup مايوديش لـ404.
    if (/^\/[a-z0-9-]+$/i.test(pathname)) {
      if (serveStatic(res, PUBLIC_DIR, pathname + '.html', req)) return;
    }
    if (serveStatic(res, PUBLIC_DIR, pathname, req)) return;

    // SPA-ish fallback to 404 page if present.
    const notFound = path.join(PUBLIC_DIR, '404.html');
    if (fs.existsSync(notFound)) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      // [ITEM-13] نفس حماية تيار الصور: خطأ قراءة لا يجوز أن يوقع العملية.
      const nfStream = fs.createReadStream(notFound);
      nfStream.on('error', (e) => {
        console.error('[stream] 404 page read failed:', e && e.message);
        try { res.destroy(); } catch (_) {}
      });
      return nfStream.pipe(res);
    }
    return sendText(res, 404, 'Not found');
  } catch (err) {
    const status = err && err.statusCode ? err.statusCode : 500;
    if (status >= 500) {
      // [FIX M12] الخطأ بيتسجل مع نفس rid اللي العميل شايفه في X-Request-Id،
      // فأي شكوى تبقى قابلة للتتبع في ثواني.
      logLine({
        t: new Date().toISOString(),
        lvl: 'error',
        rid: requestId,
        method: req.method,
        path: pathname,
        status: status,
        err: (err && err.message) || String(err),
        stack: (err && err.stack) ? String(err.stack).split('\n').slice(0, 5).join(' | ') : null,
      });
      // Never leak internal error details to the client.
      return sendJson(res, status, { error: 'server_error', requestId: requestId });
    }
    return sendJson(res, status, { error: err && err.message ? err.message : 'error', requestId: requestId });
  }
}
const server = http.createServer((req,res)=>{
  const zone=deviceClock.fromRequest(req);
  let uid=null;
  try { const u=auth.currentUser(parseCookies(req));uid=u&&u.id; if(uid&&zone)userTimezones.remember(uid,zone); }catch(_){}
  deviceClock.run(uid,zone,()=>handleRequest(req,res)).catch(()=>{if(!res.headersSent)sendJson(res,500,{error:'server_error'});else res.end();});
});

// Backups run in this process because it is the only one that can see the
// database disk. Failure to start must never take the server down.
// v38: مع تشغيل أكتر من نسخة (cluster.js) النسخة الأولى بس بتعمل الشغل الدوري.
const RUN_JOBS = process.env.EF_RUN_JOBS !== '0';
function retryReceiptDeletes() {
  try {
    Promise.resolve(require('./lib/receipt-storage').sweepDeletes()).catch(() => console.error('[receipts] deletion retry failed; operator review required'));
  } catch (_) { console.error('[receipts] deletion retry could not start'); }
}
function reconcileGooglePurchases() {
  try {
    Promise.resolve(require('./lib/google-play-reconciliation').run()).catch(() => console.error('[gplay] refund reconciliation failed; operator review required'));
  } catch (_) { console.error('[gplay] reconciliation could not start'); }
}
// [BAND1] Subscription housekeeping (close expired + stamped renewal
// reminders). Isolated like the other jobs: a load failure must never take
// startup or the maintenance loop down.
function runSubscriptionMaintenance() {
  try {
    Promise.resolve(require('./lib/subscription-maintenance').run()).catch(() => console.error('[subscriptions] maintenance run failed'));
  } catch (_) {}
}
if (RUN_JOBS) {
  retryReceiptDeletes();
  reconcileGooglePurchases();
  try { require('./lib/user-prefs').purgeExpiredDeletedTrials(); } catch (_) {}
  try { require('./lib/account-archive').purgeExpired(); } catch (_) {}
  try { require('./lib/log-retention').purgeExpiredLogs(); } catch (_) {}
  try { require('./lib/backup-scheduler').start(); }
  catch (e) { console.error('[backup] scheduler did not start:', e.message); }
  runSubscriptionMaintenance();
}

// [B18-OPS] Socket timeouts: keep-alive must outlive the load balancer idle
// timeout (60s on most LBs) or clients get random 502s; slow-loris clients are
// cut off by headers/request timeouts.
server.keepAliveTimeout = parseInt(process.env.EF_KEEPALIVE_MS || '65000', 10);
server.headersTimeout = server.keepAliveTimeout + 5000;
server.requestTimeout = parseInt(process.env.EF_REQUEST_TIMEOUT_MS || '60000', 10);

// [B18-OPS] Periodic housekeeping (cheap, idempotent, never fatal).
const maintenance = RUN_JOBS ? setInterval(() => {
  retryReceiptDeletes();
  try { require('./lib/mailer').purgeTokens(); } catch (_) {}
  try { require('./lib/idempotency').sweep(); } catch (_) {}
  try { require('./lib/user-prefs').purgeExpiredDeletedTrials(); } catch (_) {}
  try { require('./lib/account-archive').purgeExpired(); } catch (_) {}
  try { require('./lib/log-retention').purgeExpiredLogs(); } catch (_) {}
  try { require('./lib/google-play-grants').sweep(); } catch (_) {}
  runSubscriptionMaintenance();
  reconcileGooglePurchases();
}, 6 * 3600000) : null;
if (maintenance && maintenance.unref) maintenance.unref();

// [B18-OPS] Graceful shutdown: stop taking new work, let in-flight requests
// finish, stop engine workers, then exit. A hard deadline prevents hanging.
function shutdown(signal) {
  if (lifecycle.draining) return;
  lifecycle.draining = true;
  console.log('[lifecycle] ' + signal + ' received — draining');
  const deadline = setTimeout(() => process.exit(0), parseInt(process.env.EF_SHUTDOWN_GRACE_MS || '20000', 10));
  if (deadline.unref) deadline.unref();
  server.close(async () => {
    try { await require('./lib/engine-pool').close(); } catch (_) {}
    try { if (db.db && typeof db.db.close === 'function') db.db.close(); } catch (_) {}
    process.exit(0);
  });
  if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();
}
process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  console.error('[process] unhandled rejection:', reason && reason.stack ? reason.stack : reason);
});

// [ITEM-13 — شبكة أمان أخيرة للعملية]
// قبل هذا البند لم يكن في المشروع كله أي معالج uncaughtException: خطأ نادر
// واحد (كمثال تيار ملف يُحذف لحظة طلبه، قبل إضافة معالجات التيارات أعلاه)
// كان يوقع العملية وكل مستخدميها معها. القاعدة الآن:
//  • أخطاء انقطاع عميل أثناء الإرسال (EPIPE/ECONNRESET) حميدة ومعروفة السبب —
//    تُسجَّل وتبقى العملية حية، لأن حالة الخادم لم تتأثر.
//  • أي استثناء آخر مجهول: الحالة الداخلية لم تعد موثوقة، فالآمن هو الإغلاق
//    الرشيق القائم (تصريف الاتصالات ثم خروج) وترك المشرف يعيد التشغيل نظيفًا —
//    في وضع العنقود (cluster.js) يعيد الرئيس العامل وحده وباقي العمال يخدمون
//    بلا انقطاع، وفي الوضع الفردي يعيد Docker/المشرف العملية. الانهيار المفاجئ
//    في منتصف الطلبات هو ما انتهى، لا الخدمة.
let fatalShutdownStarted = false;
process.on('uncaughtException', (err) => {
  console.error('[process] uncaught exception:', err && err.stack ? err.stack : err);
  if (err && (err.code === 'EPIPE' || err.code === 'ECONNRESET' || err.code === 'ECONNABORTED')) return;
  if (fatalShutdownStarted) return;
  fatalShutdownStarted = true;
  try { shutdown('uncaughtException'); } catch (_) { process.exit(1); }
  // ضمان أخير: لو التصريف نفسه علّق، لا تبقَ عملية بحالة غير موثوقة للأبد.
  const backstop = setTimeout(() => process.exit(1), parseInt(process.env.EF_SHUTDOWN_GRACE_MS || '20000', 10) + 5000);
  if (backstop.unref) backstop.unref();
});

server.listen(PORT, () => {
  console.log('ElForma running on http://localhost:' + PORT);
  try {
    const _st = require('./lib/db').storage;
    if (_st && _st.durable) {
      console.log('[persistence] ✅ تخزين دائم عبر ' + _st.engine + ' — أوامر الأدمن هتتحفظ.');
    } else {
      console.warn('[persistence] ⚠️ التخزين محلي (' + (_st && _st.dbPath) + ') وبيعتمد على قرص المضيف. لو مفيش قرص دائم فعلي، أي اشتراك/إعلان/بروفايل هيضيع عند إعادة التشغيل. اضبط TURSO_DATABASE_URL + TURSO_AUTH_TOKEN لتخزين سحابي دائم.');
    }
  } catch (_) {}
});

module.exports = server;
