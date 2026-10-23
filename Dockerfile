# Reviewed Node 22 maintenance patch, pinned for repeatability.
# Verify native SQLite/dependencies in CI before approving production deployment.
FROM node:22.23.3-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV NODE_ENV=production
ENV EF_ENV=production
ENV PORT=8000
# Must match the mounted disk in render.yaml. Pointing this at a path
# inside the image would silently throw away every user on redeploy.
ENV EF_DATA_DIR=/var/data/elforma
# [FIX-DEPLOY-SQLITE] الفلاج في متغير بيئة كمان: لو حدّ غير أمر التشغيل
# من لوحة Render (أو شغّل npm start / node server.js) يفضل شغّال.
ENV NODE_OPTIONS=--experimental-sqlite

COPY package.json ./
COPY package-lock.json ./
# [FIX جذري] كان مفيش npm install خالص، فمكتبة libsql (اللي بتوصّل بـTurso)
# ماكانتش بتتثبّت أبداً. النتيجة: أول ما تتظبط متغيّرات Turso،
# require('libsql') بيفشل والسيرفر بيقع، فTurso يفضل صفر كتابة.
# libsql في optionalDependencies فبيتثبّت تلقائيًا مع npm install.
# [FIX v2] libsql نُقلت لـ dependencies (مش optional) — npm install هيثبتها دايماً
RUN npm ci --omit=dev --include=optional --no-audit --no-fund
COPY server.js ./
# Always available locally; CI replaces its null commit with the release SHA.
COPY build-info.json ./
# v38: تشغيل على كل الأنوية (EF_WEB_WORKERS). من غيره = عملية واحدة زي الأول.
COPY cluster.js ./
COPY api ./api
COPY lib ./lib
COPY app ./app
COPY public ./public
COPY scripts ./scripts
COPY recipe-import ./recipe-import
COPY tools/turso-to-sqlite.js ./tools/turso-to-sqlite.js

RUN mkdir -p /var/data/elforma && chown -R node:node /app /var/data/elforma

USER node
EXPOSE 8000

# [PERSISTENCE — إصلاح جذري] الأمر القديم كان:
#   rm -f /var/data/elforma/elforma.db*; node ... server.js
# يعني كان بيمسح قاعدة البيانات المحلية مع *كل* إعادة تشغيل/deploy. النتيجة:
# لو Turso مش متوصّل فعليًا (متغيّراته sync:false ولازم تتحط يدوي)، التطبيق
# بيقع على القاعدة المحلية — واللي الأمر ده كان بيمسحها في كل restart. فأي
# اشتراك/إعلان/إشعار/بروفايل الأدمن بيعمله كان بيتكتب وبعدين يتمسح فورًا، وده
# السبب الحقيقي والمثبّت لإن «كل أوامر لوحة الأدمن مالهاش تأثير على التطبيق».
# تنظيف ميتاداتا الريبليكا القديمة (WalConflict) اتنقل جوه lib/db.js وبيتنفّذ
# بأمان *فقط* في وضع replica ولمّا القاعدة الأساسية تكون ناقصة — من غير ما
# يلمس داتا سليمة أبدًا. مفيش أي مسح للقاعدة عند التشغيل بعد كده.
CMD ["node", "--experimental-sqlite", "cluster.js"]
