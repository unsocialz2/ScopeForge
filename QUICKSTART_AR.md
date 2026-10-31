# ScopeForge — تشغيل سريع على Kali / WSL

الملف اللي رفعته متضمّن في `inputs/xiaomi_scope.csv`، والأداة بتقرأ منه **43 نطاق Wildcard** وبتتجاهل الـ APK/Hardware.

**1) فك الضغط وادخل المجلد:**

```bash
unzip ScopeForge_v1_Xiaomi.zip
cd ScopeForge
```

**2) نزّل الاعتماديات والمتصفح مرة واحدة:**

```bash
./setup.sh
```

لو Chromium اشتكى من مكتبات Linux ناقصة: `source .venv/bin/activate && python -m playwright install --with-deps chromium`.

**3) اجمع كل الأسماء الممكن العثور عليها من المصادر العامة بدون لمس مواقع التارجت:**

```bash
./run_xiaomi.sh passive
```

**4) بعد التأكد من صلاحية الاختبار وسقف الـ Rate Limit الحالي للبرنامج، شغّل فحص الويب والصور:**

```bash
./run_xiaomi.sh active
```

**5) افتح التقرير:**

`results/xiaomi/report.html`

الـ Dashboard تقدر تستخدمه Offline وتبحث وتفلتر وتشوف الـ Screenshots لكل Host وتعمل Star وتكتب Notes وتصدّر قائمة المراجعة. الـ `404/410` مخفية من العرض الأساسي، والـ `500` بتظهر في تبويب منفصل بدل ما تتصنّف ميتة.

**لإزالة الحدّ الأقصى لعدد الـ Hosts المكتشفة وصورها:**

```bash
source .venv/bin/activate
python scopeforge.py --scope inputs/xiaomi_scope.csv --out results/all \
  --authorized --max-hosts 0 --max-screenshots 0 --workers 4
```

مافيش خدمة مجانية تضمن لك **كل** أسماء الـ DNS الممكنة. النتايج حسب تغطية كل مصدر مجاني، وسيرفرات المصادر نفسها ممكن تطبق Rate Limits. Subfinder اختياري لكن بيرفع تغطية الـ Discovery جدًا. النتائج المهمة مجرد مرشحات للمراجعة، مش ثغرات مؤكدة.

جرب **`demo/report.html`** الأول. الديمو Fictional بالكامل ومش فيه أي نتائج حقيقية من Xiaomi.
