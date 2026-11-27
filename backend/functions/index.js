"use strict";

const crypto = require("node:crypto");
const admin = require("firebase-admin");
const { onCall, HttpsError } = require("firebase-functions/v2/https");

const authRateLimitBuckets = new Map();

admin.initializeApp({
  databaseURL: "https://wadi-bina-f9a77-default-rtdb.asia-southeast1.firebasedatabase.app/"
});

const ROLE_ALIASES = {
  owner: "owner",
  "مالك": "owner",
  gm: "gm",
  super_admin: "super_admin",
  "مدير عام": "super_admin",
  management_accountant: "management_accountant",
  "محاسب الإدارة": "management_accountant",
  branch_admin: "branch_admin",
  branch_manager: "branch_admin",
  "مدير فرع": "branch_admin",
  "مدير": "branch_admin",
  accountant: "accountant",
  "محاسب": "accountant",
  chief_accountant: "chief_accountant",
  "محاسب رئيسي": "chief_accountant",
  branch_accountant: "branch_accountant",
  "محاسب فرع": "branch_accountant",
  branch_manager_accountant: "branch_manager_accountant",
  "مدير فرع ومحاسب": "branch_manager_accountant",
  staff: "staff",
  employee: "staff",
  "موظف": "staff",
  driver: "driver",
  "سائق": "driver"
};

const BRANCH_ALIASES = {
  all: "all",
  "جميع الفروع": "all",
  head_office: "head_office",
  main: "head_office",
  "الفرع الرئيسي": "head_office",
  ajman: "ajman",
  "فرع عجمان": "ajman",
  abudhabi: "abudhabi",
  "فرع ابوظبي": "abudhabi",
  "فرع أبوظبي": "abudhabi",
  bani_yas: "bani_yas",
  "فرع بني ياس": "bani_yas",
  yemen: "yemen",
  "فرع اليمن": "yemen",
  aden_branch: "aden_branch",
  aden: "yemen",
  "فرع عدن": "aden_branch",
  mukalla_branch: "mukalla_branch",
  mukalla: "yemen",
  "فرع المكلا": "mukalla_branch",
  muscat: "muscat",
  oman: "muscat",
  "فرع عمان": "muscat",
  "فرع مسقط": "muscat",
  ain: "ain",
  "فرع العين": "ain"
};

function constantTimeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left), "utf8");
  const rightBuffer = Buffer.from(String(right), "utf8");
  return leftBuffer.length === rightBuffer.length
    && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function passwordMatches(profile, password) {
  if (typeof profile.passwordHash === "string") {
    const storedHash = profile.passwordHash.toLowerCase();
    const suppliedHash = crypto.createHash("sha256").update(password, "utf8").digest("hex");
    return /^[a-f0-9]{64}$/.test(storedHash)
      && constantTimeEqual(storedHash, suppliedHash);
  }

  return typeof profile.password === "string"
    && constantTimeEqual(profile.password, password);
}

function normalizeRole(role) {
  const roleText = String(role || "employee").trim();
  return ROLE_ALIASES[roleText] || ROLE_ALIASES[roleText.toLowerCase()] || roleText.toLowerCase();
}

function normalizeBranchId(profile) {
  const branchText = String(profile.branchId || profile.branch || "ajman").trim();
  const branchId = BRANCH_ALIASES[branchText]
    || BRANCH_ALIASES[branchText.toLowerCase()]
    || branchText.toLowerCase();
  if (!/^[a-z0-9_-]{1,64}$/.test(branchId)) {
    throw new HttpsError("failed-precondition", "حساب المستخدم لا يحتوي على رمز فرع صالح.");
  }
  return branchId;
}

function enforceRateLimit(key, limit) {
  const keyHash = crypto.createHash("sha256").update(key, "utf8").digest("hex");
  const now = Date.now();
  if (authRateLimitBuckets.size > 5000) {
    for (const [storedKey, storedBucket] of authRateLimitBuckets) {
      if (now >= storedBucket.windowEndsAt) authRateLimitBuckets.delete(storedKey);
    }
  }
  const bucket = authRateLimitBuckets.get(keyHash);
  if (!bucket || now >= bucket.windowEndsAt) {
    authRateLimitBuckets.set(keyHash, { count: 1, windowEndsAt: now + 60_000 });
    return;
  }
  if (bucket.count >= limit) {
    throw new HttpsError("resource-exhausted", "محاولات تسجيل الدخول كثيرة؛ أعد المحاولة بعد دقيقة.");
  }
  bucket.count++;
}

const MANAGER_ROLES = new Set([
  "owner",
  "gm",
  "super_admin",
  "management_accountant",
  "branch_admin",
  "branch_manager",
  "branch_manager_accountant"
]);
const SUPPORTED_ROLES = new Set(Object.values(ROLE_ALIASES));

exports.authenticateUser = onCall({
  region: "asia-southeast1",
  maxInstances: 3
}, async (request) => {
  const username = typeof request.data?.username === "string"
    ? request.data.username.trim().toLocaleLowerCase("ar")
    : "";
  const password = typeof request.data?.password === "string"
    ? request.data.password
    : "";
  const managerOnly = request.data?.managerOnly === true;

  if ((!managerOnly && !username) || username.length > 120 || !password || password.length > 1024) {
    throw new HttpsError("invalid-argument", "اسم المستخدم أو كلمة المرور غير صالحة.");
  }

  if (username) enforceRateLimit(`username:${username}`, 12);
  else enforceRateLimit(`manager-password:${crypto.createHash("sha256").update(password, "utf8").digest("hex")}`, 12);
  if (request.rawRequest?.ip) enforceRateLimit(`ip:${request.rawRequest.ip}`, 40);

  let usersSnapshot;
  try {
    usersSnapshot = await admin.database().ref("users").get();
  } catch (error) {
    console.error("Could not read account profiles for sign-in.", error);
    throw new HttpsError("internal", "تعذر التحقق من الحساب حالياً.");
  }

  const profiles = usersSnapshot.val() || {};
  const matches = Object.entries(profiles).filter(([uid, profile]) => {
    if (!profile || profile.active !== true) return false;
    const profileUsername = String(
      profile.username || profile.fullName || profile.name || uid
    ).trim().toLocaleLowerCase("ar");
    if (username && profileUsername !== username) return false;
    if (managerOnly && !MANAGER_ROLES.has(normalizeRole(profile.role))) return false;
    return passwordMatches(profile, password);
  });

  if (matches.length !== 1) {
    throw new HttpsError(
      "unauthenticated",
      managerOnly
        ? "كلمة المرور غير صحيحة أو لا يرتبط بها حساب إداري نشط."
        : "اسم المستخدم أو كلمة المرور غير صحيحة."
    );
  }

  const [uid, profile] = matches[0];
  const role = normalizeRole(profile.role);
  const roleClaim = String(profile.role || "employee").trim();
  const branchId = normalizeBranchId(profile);
  if (!SUPPORTED_ROLES.has(role) || roleClaim.length > 64) {
    throw new HttpsError("failed-precondition", "حساب المستخدم لا يحتوي على صلاحية صالحة.");
  }

  try {
    if (typeof profile.passwordHash !== "string") {
      await admin.database().ref(`users/${uid}`).update({
        passwordHash: crypto.createHash("sha256").update(password, "utf8").digest("hex"),
        password: null
      });
    }
    const customToken = await admin.auth().createCustomToken(uid, {
      role: roleClaim,
      branchId
    });
    return { customToken };
  } catch (error) {
    console.error("Could not create an authenticated application session.", error);
    throw new HttpsError("internal", "تعذر تسجيل الدخول إلى النظام حالياً.");
  }
});

exports.createPasswordResetRequest = onCall({
  region: "asia-southeast1",
  maxInstances: 3
}, async (request) => {
  const username = typeof request.data?.username === "string"
    ? request.data.username.trim()
    : "";
  const phone = typeof request.data?.phone === "string"
    ? request.data.phone.trim()
    : "";
  const branch = typeof request.data?.branch === "string"
    ? request.data.branch.trim()
    : "";
  const phoneDigits = phone.replace(/\D/g, "");

  if (!username || username.length > 120 || phone.length > 80
      || phoneDigits.length < 7 || !branch || branch.length > 80) {
    throw new HttpsError("invalid-argument", "بيانات طلب استعادة كلمة المرور غير صالحة.");
  }

  enforceRateLimit(`reset-request-user:${username.toLocaleLowerCase("ar")}`, 3);
  if (request.rawRequest?.ip) enforceRateLimit(`reset-request-ip:${request.rawRequest.ip}`, 5);
  const branchId = normalizeBranchId({ branchId: branch });
  const requestRef = admin.database().ref("passwordResetRequests").push();
  await requestRef.set({
    username,
    phone,
    branch: branchId,
    status: "pending",
    requestedAt: Date.now()
  });
  if (!requestRef.key) {
    throw new HttpsError("internal", "تعذر إنشاء معرّف طلب الاستعادة.");
  }
  return { requestId: requestRef.key };
});

exports.completeApprovedPasswordReset = onCall({
  region: "asia-southeast1",
  maxInstances: 3
}, async (request) => {
  const requestId = typeof request.data?.requestId === "string"
    ? request.data.requestId.trim()
    : "";
  const password = typeof request.data?.password === "string"
    ? request.data.password
    : "";

  if (!/^[A-Za-z0-9_-]{10,128}$/.test(requestId)
      || password.length < 6
      || password.length > 1024) {
    throw new HttpsError("invalid-argument", "بيانات استعادة كلمة المرور غير صالحة.");
  }

  enforceRateLimit(`reset:${requestId}`, 5);
  if (request.rawRequest?.ip) enforceRateLimit(`reset-ip:${request.rawRequest.ip}`, 20);

  const requestRef = admin.database().ref(`passwordResetRequests/${requestId}`);
  const snapshot = await requestRef.get();
  const resetRequest = snapshot.val();
  if (!resetRequest || resetRequest.status !== "approved" || !resetRequest.targetUid) {
    throw new HttpsError("failed-precondition", "لم يعد طلب الاستعادة معتمداً.");
  }

  const userRef = admin.database().ref(`users/${resetRequest.targetUid}`);
  const userSnapshot = await userRef.get();
  const profile = userSnapshot.val();
  const requestUsername = String(resetRequest.username || "").trim().toLocaleLowerCase("ar");
  const profileUsername = String(profile?.username || "").trim().toLocaleLowerCase("ar");
  if (!profile || profile.active !== true || !requestUsername || requestUsername !== profileUsername) {
    throw new HttpsError("failed-precondition", "تعذر مطابقة الحساب المعتمد أو أن الحساب غير نشط.");
  }

  const lock = await requestRef.transaction((current) => {
    if (!current || current.status !== "approved" || current.targetUid !== resetRequest.targetUid) {
      return;
    }
    return { ...current, status: "processing", processingAt: Date.now() };
  });
  if (!lock.committed) {
    throw new HttpsError("failed-precondition", "بدأت معالجة هذا الطلب مسبقاً.");
  }

  const passwordHash = crypto.createHash("sha256").update(password, "utf8").digest("hex");
  try {
    await userRef.update({ passwordHash, password: null });
    await requestRef.update({ status: "completed", completedAt: Date.now() });
    try {
      await admin.database().ref(`systemAuditLogs/reset_${requestId}`).set({
        uid: resetRequest.targetUid,
        actor: "النظام",
        actorUsername: null,
        action: "SELF_SERVICE_PASSWORD_RESET",
        targetUsername: resetRequest.username,
        details: { requestId },
        timestamp: Date.now()
      });
    } catch (auditError) {
      console.error("Could not write the password-reset audit log.", auditError);
    }
    return { completed: true, username: resetRequest.username };
  } catch (error) {
    console.error("Could not complete approved password reset.", error);
    if (error instanceof HttpsError) throw error;
    await requestRef.update({ status: "approved", processingAt: null });
    throw new HttpsError("internal", "تعذر إكمال تغيير كلمة المرور.");
  }
});
