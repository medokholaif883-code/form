'use strict';
// v38: تشغيل السيرفر على كل أنوية المعالج.
//
// تجربة الضغط على السيرفر الحقيقي (2 نواة) بينت إن عملية واحدة بتقف عند
// ~400 طلب/ثانية والنواة التانية فاضية. هنا بنشغل نسخة من server.js على كل
// نواة (EF_WEB_WORKERS)، والنظام كله متصمم لكده من الأول:
//  * الكاش بيتربط برقم مراجعة المستخدم في قاعدة البيانات (EF_MULTI_INSTANCE=1)
//    فمفيش نسخة ممكن ترجع بيانات قديمة بعد ما نسخة تانية تكتب.
//  * أقفال الدخول متخزنة في SQLite، وإعدادات الأدمن بتتحدث في كل النسخ خلال 5 ثواني.
//  * النسخة الأولى بس هي اللي بتعمل النسخة الاحتياطية والتنظيف (EF_RUN_JOBS).
//  * النسخ بتبدأ واحدة ورا التانية عشان تحديثات قاعدة البيانات وقت التشغيل
//    ماتتنفذش مرتين في نفس اللحظة.
// EF_WEB_WORKERS=1 (أو مش متحدد) = نفس التشغيل القديم بالظبط (عملية واحدة).
const cluster = require('node:cluster');
const os = require('node:os');

const cores = os.availableParallelism ? os.availableParallelism() : os.cpus().length;
const raw = String(process.env.EF_WEB_WORKERS || '1').trim();
const wanted = raw === 'auto' ? cores : parseInt(raw, 10);
const COUNT = Math.max(1, Math.min(cores, Number.isFinite(wanted) ? wanted : 1));

if (COUNT <= 1 || !cluster.isPrimary) {
  require('./server.js');
} else {
  require('./lib/cluster-metrics').attachPrimary();
  const GRACE = parseInt(process.env.EF_SHUTDOWN_GRACE_MS || '20000', 10) + 5000;
  const roles = new Map(); // worker.id -> index
  let stopping = false;
  const restarts = [];

  // [ITEM-32] حصة كل نسخة ويب من ميزانية عمال المحرك على الجهاز كله:
  // الميزانية = الأنوية − 1 (نواة محفوظة للويب/SQLite/النظام — درس v38)،
  // وبتتقسم على نسخ الويب بتصعيد الكسر، فالمجموع الكلي ≈ الأنوية − 1 إلى
  // الأنوية (نسخة على كل نواة = عامل لكل نسخة زي قبل كده بالظبط، ونسخ أقل
  // من الأنوية = حصة أكبر لكل نسخة). سقف الذاكرة الآمن بيُفرض جوه
  // lib/engine-pool.js فوق أي قيمة توصل له. القيمة الصريحة من البيئة تكسب.
  const engineShare = Math.max(1, Math.ceil((cores - 1) / COUNT));
  function envFor(index) {
    return {
      EF_MULTI_INSTANCE: '1',
      EF_RUN_JOBS: index === 0 ? '1' : '0',
      EF_WORKER_INDEX: String(index),
      ENGINE_POOL_SIZE: process.env.ENGINE_POOL_SIZE || String(engineShare),
    };
  }
  function start(index) {
    return new Promise((resolve) => {
      const worker = cluster.fork(envFor(index));
      roles.set(worker.id, index);
      let settled = false;
      const done = () => { if (!settled) { settled = true; resolve(); } };
      worker.once('listening', done);
      worker.once('exit', done);
    });
  }
  cluster.on('exit', (worker, code, signal) => {
    const index = roles.get(worker.id);
    roles.delete(worker.id);
    if (stopping || index === undefined) return;
    console.error('[cluster] worker ' + index + ' exited (' + (signal || code) + ') — restarting');
    const now = Date.now();
    restarts.push(now);
    while (restarts.length && now - restarts[0] > 60000) restarts.shift();
    // لو بتقع على طول (أكتر من 10 مرات في الدقيقة) بنستنى شوية بدل ما نلف في دايرة.
    setTimeout(() => { if (!stopping) start(index); }, restarts.length > 10 ? 10000 : 1000);
  });
  function shutdown(signal) {
    if (stopping) return;
    stopping = true;
    console.log('[cluster] ' + signal + ' received — stopping ' + roles.size + ' workers');
    for (const id of Object.keys(cluster.workers)) {
      try { cluster.workers[id].process.kill('SIGTERM'); } catch (_) {}
    }
    const deadline = setTimeout(() => process.exit(0), GRACE);
    if (deadline.unref) deadline.unref();
    const check = setInterval(() => {
      if (!Object.keys(cluster.workers).length) { clearInterval(check); process.exit(0); }
    }, 200);
  }
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
  // [ITEM-13] رئيس العنقود نفسه: استثناء غير ملتقط يُسجَّل ثم إغلاق رشيق
  // (إيقاف العمال بالترتيب) بدل انهيار Node الافتراضي — المشرف الخارجي يعيد
  // التشغيل من حالة نظيفة. العمال أنفسهم تغطيهم شبكة server.js.
  process.on('uncaughtException', (err) => {
    console.error('[cluster] uncaught exception in primary:', err && err.stack ? err.stack : err);
    try { shutdown('uncaughtException'); } catch (_) { process.exit(1); }
  });
  (async () => {
    console.log('[cluster] starting ' + COUNT + ' web workers on ' + cores + ' cores');
    for (let i = 0; i < COUNT; i++) await start(i);
  })();
}
