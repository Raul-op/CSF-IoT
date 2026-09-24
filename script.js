/* ==========================================================
   VIGIL — Mobile App Security & Cloud Threat Detection Simulator
   Pure vanilla JS. All data lives in localStorage. No backend.
   ========================================================== */
(function () {
  'use strict';

  var STORAGE_KEY = 'sentinel_state_v1';

  var GEO_OK = [['London, UK', '81.2.'], ['Toronto, CA', '99.244.']];
  var GEO_BAD = [['Moscow, RU', '185.220.'], ['Lagos, NG', '102.89.'], ['Shenzhen, CN', '114.114.'], ['Sao Paulo, BR', '177.71.']];

  var APP_NAMES = [
    'Flashlight Pro',
    'QuickPhoto Editor',
    'ChatWave Messenger',
    'Coin Clicker Game',
    'VPN Shield Lite'
  ];

  var DEVICE_LABELS = {
    screenLock: 'Screen Lock Enabled',
    encryption: 'Device Encryption Enabled',
    osUpdate: 'Operating System Up To Date',
    remoteWipe: 'Remote Wipe Capability Enabled'
  };

  var TITLES = {
    dashboard: 'Dashboard',
    mobile: 'Mobile Security',
    cloud: 'Cloud Threat Detection',
    alerts: 'Security Alerts',
    logs: 'Activity Logs',
    simulator: 'Threat Simulator'
  };

  /* ---------------------------------------------------------
     STATE
     --------------------------------------------------------- */
  function defaultState() {
    return {
      events: [],
      alerts: [],
      mobile: {
        failedLoginCount: 0,
        publicWifi: false,
        device: { screenLock: true, encryption: true, osUpdate: true, remoteWipe: true },
        apps: APP_NAMES.map(function (name) {
          return { name: name, perms: { camera: false, location: false, contacts: false, sms: false, mic: false } };
        })
      },
      cloud: { failedLoginCount: 0, requestCount: 0 }
    };
  }

  function seedDemo(s) {
    var now = Date.now();
    var seed = [
      ['cloud', 'Successful Login', 'User logged in successfully from a recognized device and IP address', 'safe', 9],
      ['mobile', 'App Permission Scan', 'All installed apps have minimal, appropriate permissions', 'safe', 7],
      ['cloud', 'Failed Login', 'Failed login attempt #1 on cloud account — incorrect password', 'warning', 5],
      ['mobile', 'Public Wi-Fi Connected', 'Device connected to an unencrypted public Wi-Fi network', 'warning', 4],
      ['cloud', 'Suspicious IP Access', 'Login attempt originated from a blocklisted or geographically anomalous IP address', 'threat', 2],
      ['mobile', 'Unknown App Detected', 'Sideloaded application "com.unknown.sideload482" found outside the official app store', 'threat', 1]
    ];
    seed.forEach(function (row) {
      var ev = { id: uid(), time: now - row[4] * 60000, source: row[0], type: row[1], description: row[2], risk: row[3], origin: genOrigin(row[0], row[3]) };
      s.events.push(ev);
      if (ev.risk !== 'safe') {
        s.alerts.push({ id: 'a' + ev.id, eventId: ev.id, title: ev.type, description: ev.description, severity: ev.risk, time: ev.time, resolved: false, resolvedAt: null });
      }
    });
    s.events.sort(function (a, b) { return b.time - a.time; });
    s.alerts.sort(function (a, b) { return b.time - a.time; });
    return s;
  }

  function load() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return seedDemo(defaultState());
      var parsed = JSON.parse(raw);
      if (!parsed || !parsed.events || !parsed.alerts || !parsed.mobile || !parsed.cloud) return seedDemo(defaultState());
      return parsed;
    } catch (e) {
      console.error('Vigil: failed to load state, starting fresh.', e);
      return seedDemo(defaultState());
    }
  }

  function save() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (e) {
      console.error('Vigil: failed to save state.', e);
    }
  }

  var state = load();

  /* ---------------------------------------------------------
     HELPERS
     --------------------------------------------------------- */
  function uid() {
    return 'e' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
    });
  }

  function fmtTime(ts) {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function fmtDate(ts) {
    var d = new Date(ts);
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' \u00B7 ' + fmtTime(ts);
  }

  function badgeHtml(risk) {
    var label = risk.charAt(0).toUpperCase() + risk.slice(1);
    return '<span class="badge ' + risk + '">' + label + '</span>';
  }

  function sourceLabel(source) {
    return source === 'mobile' ? 'Mobile' : 'Cloud';
  }

  /* ---------------------------------------------------------
     CORE: EVENTS + ALERTS
     --------------------------------------------------------- */
  function addEvent(source, type, description, risk) {
    var ev = { id: uid(), time: Date.now(), source: source, type: type, description: description, risk: risk, origin: genOrigin(source, risk) };
    state.events.unshift(ev);
    if (state.events.length > 500) state.events.length = 500;
    if (risk === 'warning' || risk === 'threat') addAlert(ev);
    save();
    return ev;
  }

  function addAlert(ev) {
    state.alerts.unshift({
      id: 'a' + ev.id,
      eventId: ev.id,
      title: ev.type,
      description: ev.description,
      severity: ev.risk,
      time: ev.time,
      resolved: false,
      resolvedAt: null
    });
  }

  /* Realistic context: where an event came from, and what to do about it */
  function genOrigin(source, risk) {
    var pool = risk === 'safe' ? GEO_OK : risk === 'threat' ? GEO_BAD : GEO_OK.concat(GEO_BAD);
    var g = pool[Math.floor(Math.random() * pool.length)];
    var rnd = function () { return Math.floor(Math.random() * 254) + 1; };
    return {
      ip: g[1] + rnd() + '.' + rnd(), geo: g[0],
      device: source === 'mobile' ? 'Pixel 8, Android 15' : (risk === 'safe' ? 'Chrome 128, macOS' : 'Unrecognized client')
    };
  }
  function originHtml(o) {
    return o ? '<span class="mono">' + escapeHtml(o.ip) + '</span><small>' + escapeHtml(o.geo + ' \u00B7 ' + o.device) + '</small>' : '\u2014';
  }
  var ADVICE = {
    'Unknown Device': 'Ask the user to confirm the device, or remove it from trusted devices.',
    'Failed Login': 'Check with the account owner and make sure MFA is turned on.',
    'Brute-Force': 'Block the source IP and force a password reset.',
    'Suspicious IP': 'Add the IP to the blocklist and revoke active sessions.',
    'Unknown App': 'Uninstall the app and run a full malware scan.',
    'Public Wi-Fi': 'Switch to cellular data or connect through a VPN.',
    'Permission': 'Revoke permissions the app does not need in device settings.',
    'Request': 'Apply rate limiting and review the API key sending the traffic.',
    'Password': 'Require a longer passphrase and turn on MFA.',
    'Device': 'Turn on screen lock, encryption and OS updates.'
  };
  function adviceFor(type) {
    for (var k in ADVICE) if (type.indexOf(k) !== -1) return ADVICE[k];
    return '';
  }
  function ago(ts) {
    var s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 60) return s + 's ago';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' min ago';
    var h = Math.floor(m / 60);
    return h < 24 ? h + ' h ago' : Math.floor(h / 24) + ' d ago';
  }

  /* Live monitoring: background activity arrives at random intervals */
  var liveTimer = null, quietToasts = false;
  var LIVE_CLOUD = ['normal', 'normal', 'normal', 'failed', 'unknown-device', 'excessive-requests', 'suspicious-ip'];
  var LIVE_MOBILE = ['strong-pw', 'strong-pw', 'failed-login', 'public-wifi', 'unknown-app'];
  function pick(a) { return a[Math.floor(Math.random() * a.length)]; }
  function liveTick() {
    liveTimer = setTimeout(function () {
      quietToasts = true; // only threats interrupt while live
      if (Math.random() < 0.6) simulateCloudEvent(pick(LIVE_CLOUD)); else simulateMobileEvent(pick(LIVE_MOBILE));
      quietToasts = false;
      liveTick();
    }, 3000 + Math.random() * 6000);
  }
  function setLive(on) {
    clearTimeout(liveTimer);
    if (on) liveTick();
  }

  function computeScore() {
    var active = state.alerts.filter(function (a) { return !a.resolved; });
    var warn = active.filter(function (a) { return a.severity === 'warning'; }).length;
    var threat = active.filter(function (a) { return a.severity === 'threat'; }).length;
    var score = 100 - warn * 4 - threat * 10;
    return Math.max(0, Math.min(100, score));
  }

  /* ---------------------------------------------------------
     TOASTS
     --------------------------------------------------------- */
  function toast(type, title, message) {
    if (quietToasts && type !== 'threat') return;
    var stack = document.getElementById('toastStack');
    var el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = '<strong>' + escapeHtml(title) + '</strong><span>' + escapeHtml(message) + '</span>';
    stack.appendChild(el);
    setTimeout(function () { el.remove(); }, 4000);
  }

  /* ---------------------------------------------------------
     RENDER: DASHBOARD
     --------------------------------------------------------- */
  function renderDashboard() {
    var score = computeScore();
    document.getElementById('scoreNum').textContent = score;

    var ring = document.getElementById('scoreRing');
    var circumference = 2 * Math.PI * 60;
    ring.style.strokeDasharray = String(circumference);
    ring.style.strokeDashoffset = String(circumference * (1 - score / 100));

    var color = 'var(--safe)', verdict = 'System nominal';
    if (score < 50) { color = 'var(--threat)'; verdict = 'Critical risk \u2014 immediate action needed'; }
    else if (score < 80) { color = 'var(--warning)'; verdict = 'Elevated risk \u2014 review alerts'; }
    ring.style.stroke = color;
    document.getElementById('scoreVerdict').textContent = verdict;

    var safeCount = state.events.filter(function (e) { return e.risk === 'safe'; }).length;
    var warnCount = state.events.filter(function (e) { return e.risk === 'warning'; }).length;
    var threatCount = state.events.filter(function (e) { return e.risk === 'threat'; }).length;
    var activeAlerts = state.alerts.filter(function (a) { return !a.resolved; }).length;

    document.getElementById('statSafe').textContent = safeCount;
    document.getElementById('statWarning').textContent = warnCount;
    document.getElementById('statThreat').textContent = threatCount;
    document.getElementById('statAlerts').textContent = activeAlerts;

    var navBadge = document.getElementById('navAlertBadge');
    navBadge.textContent = activeAlerts;
    navBadge.dataset.zero = activeAlerts === 0 ? '1' : '0';

    var recent = state.events.slice(0, 8);
    document.querySelector('#recentActivityTable tbody').innerHTML = recent.map(function (ev) {
      return '<tr><td>' + fmtTime(ev.time) + '</td><td>' + sourceLabel(ev.source) + '</td><td>' +
        escapeHtml(ev.type) + '</td><td>' + badgeHtml(ev.risk) + '</td></tr>';
    }).join('');
    document.getElementById('recentEmpty').hidden = recent.length > 0;
  }

  /* ---------------------------------------------------------
     RENDER: MOBILE SECURITY
     --------------------------------------------------------- */
  function appRisk(app) {
    var count = Object.keys(app.perms).filter(function (k) { return app.perms[k]; }).length;
    if (count === 0) return 'safe';
    if (count <= 2) return 'warning';
    return 'threat';
  }

  function renderAppPermTable() {
    var tbody = document.querySelector('#appPermTable tbody');
    tbody.innerHTML = state.mobile.apps.map(function (app, i) {
      var perms = ['camera', 'location', 'contacts', 'sms', 'mic'];
      var cells = perms.map(function (p) {
        return '<td><input type="checkbox" data-app="' + i + '" data-perm="' + p + '" ' + (app.perms[p] ? 'checked' : '') + '/></td>';
      }).join('');
      return '<tr><td>' + escapeHtml(app.name) + '</td>' + cells + '<td>' + badgeHtml(appRisk(app)) + '</td></tr>';
    }).join('');
  }

  function renderDeviceChecklist() {
    var wrap = document.getElementById('deviceChecklist');
    wrap.innerHTML = Object.keys(DEVICE_LABELS).map(function (key) {
      var on = state.mobile.device[key];
      return '<div class="check-item"><label><input type="checkbox" data-device="' + key + '" ' + (on ? 'checked' : '') +
        '/>' + DEVICE_LABELS[key] + '</label>' + badgeHtml(on ? 'safe' : 'threat') + '</div>';
    }).join('');
  }

  function renderMobile() {
    document.getElementById('failedLoginCounter').textContent = state.mobile.failedLoginCount;
    document.getElementById('wifiToggle').checked = state.mobile.publicWifi;
    renderAppPermTable();
    renderDeviceChecklist();
  }

  function pwStrength(pw) {
    if (!pw) return { pct: 0, label: '\u2014', risk: null };
    var score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    var common = ['password', '123456', 'qwerty', 'letmein', 'admin', '123456789', 'iloveyou', '111111', 'abc123'];
    if (common.indexOf(pw.toLowerCase()) !== -1) score = 0;

    if (score <= 1) return { pct: 20, label: 'Weak', risk: 'threat' };
    if (score <= 3) return { pct: 60, label: 'Medium', risk: 'warning' };
    return { pct: 100, label: 'Strong', risk: 'safe' };
  }

  /* ---------------------------------------------------------
     RENDER: CLOUD
     --------------------------------------------------------- */
  function renderCloud() {
    document.getElementById('cloudFailCounter').textContent = state.cloud.failedLoginCount;
    document.getElementById('cloudReqCounter').textContent = state.cloud.requestCount;
  }

  function simulateCloudEvent(kind) {
    switch (kind) {
      case 'normal':
        state.cloud.failedLoginCount = 0;
        addEvent('cloud', 'Successful Login', 'User logged in successfully from a recognized device and IP address', 'safe');
        toast('safe', 'Safe event logged', 'Normal login recorded');
        break;
      case 'failed': {
        state.cloud.failedLoginCount++;
        var c = state.cloud.failedLoginCount;
        if (c >= 5) {
          addEvent('cloud', 'Brute-Force Attempt', c + ' consecutive failed login attempts detected on cloud account', 'threat');
          toast('threat', 'Threat detected', 'Failed logins escalated to brute-force');
          state.cloud.failedLoginCount = 0;
        } else {
          addEvent('cloud', 'Failed Login', 'Failed login attempt #' + c + ' \u2014 incorrect password', 'warning');
          toast('warning', 'Warning logged', 'Failed cloud login attempt');
        }
        break;
      }
      case 'bruteforce':
        state.cloud.failedLoginCount = 0;
        addEvent('cloud', 'Brute-Force Attack', 'Multiple rapid failed logins detected from a single source \u2014 classic brute-force pattern', 'threat');
        toast('threat', 'Threat detected', 'Brute-force attack simulated');
        break;
      case 'unknown-device': {
        var risk = Math.random() < 0.6 ? 'warning' : 'threat';
        addEvent('cloud', 'Unknown Device Login', 'Login detected from a device fingerprint never seen on this account before', risk);
        toast(risk, risk === 'threat' ? 'Threat detected' : 'Warning logged', 'Unrecognized device login');
        break;
      }
      case 'suspicious-ip':
        addEvent('cloud', 'Suspicious IP Access', 'Login attempt originated from a blocklisted or geographically anomalous IP address', 'threat');
        toast('threat', 'Threat detected', 'Suspicious IP flagged');
        break;
      case 'excessive-requests': {
        state.cloud.requestCount += Math.floor(Math.random() * 40) + 15;
        var r = state.cloud.requestCount;
        if (r > 100) {
          addEvent('cloud', 'Excessive Request Rate', r + ' requests/min detected from account \u2014 possible DDoS or scraping activity', 'threat');
          toast('threat', 'Threat detected', 'Excessive request rate detected');
          state.cloud.requestCount = 0;
        } else {
          addEvent('cloud', 'Elevated Request Rate', r + ' requests/min detected \u2014 above baseline but under threshold', 'warning');
          toast('warning', 'Warning logged', 'Elevated request rate');
        }
        break;
      }
    }
    save();
    renderAll();
  }

  function simulateMobileEvent(kind) {
    switch (kind) {
      case 'strong-pw':
        addEvent('mobile', 'Password Updated', 'User set a strong password meeting all complexity requirements', 'safe');
        toast('safe', 'Safe event logged', 'Strong password set');
        break;
      case 'weak-pw':
        addEvent('mobile', 'Weak Password Set', 'User set a short, easily guessable password', 'warning');
        toast('warning', 'Warning logged', 'Weak password detected');
        break;
      case 'failed-login':
        document.getElementById('failLoginBtn').click(); // same escalation rules as the Mobile tab
        break;
      case 'unknown-app':
        addEvent('mobile', 'Unknown App Detected', 'Sideloaded application found outside the official app store', 'threat');
        toast('threat', 'Threat detected', 'Unknown app installed');
        break;
      case 'public-wifi':
        addEvent('mobile', 'Public Wi-Fi Connected', 'Device connected to an unencrypted public Wi-Fi network', 'warning');
        toast('warning', 'Warning logged', 'Public Wi-Fi risk logged');
        break;
      case 'risky-permission':
        addEvent('mobile', 'Risky Permission Grant', 'An app was granted camera, contacts and SMS access simultaneously', 'threat');
        toast('threat', 'Threat detected', 'Excessive permission grant');
        break;
      case 'device-unsecured':
        addEvent('mobile', 'Device Left Unsecured', 'Screen lock and encryption were both found disabled on the device', 'threat');
        toast('threat', 'Threat detected', 'Device security disabled');
        break;
    }
    save();
    renderAll();
  }

  /* ---------------------------------------------------------
     RENDER: ALERTS
     --------------------------------------------------------- */
  function renderAlerts() {
    var showResolved = document.getElementById('showResolvedToggle').checked;
    var list = state.alerts.filter(function (a) { return showResolved ? true : !a.resolved; });
    var wrap = document.getElementById('alertList');
    wrap.innerHTML = list.map(function (a) {
      var icon = a.severity === 'threat' ? 'i-x' : 'i-alert';
      var resolveBtn = a.resolved ? '' :
        '<button class="btn primary" data-resolve="' + a.id + '"><svg><use href="#i-check"/></svg>Resolve</button>';
      return '<div class="alert-card ' + a.severity + (a.resolved ? ' resolved' : '') + '">' +
        '<svg><use href="#' + icon + '"/></svg>' +
        '<div class="alert-body">' +
          '<div class="alert-top"><span class="alert-title">' + escapeHtml(a.title) + '</span>' + badgeHtml(a.severity) + '</div>' +
          '<p class="alert-desc">' + escapeHtml(a.description) + '</p>' +
          (adviceFor(a.title) ? '<p class="alert-advice"><strong>Next step:</strong> ' + escapeHtml(adviceFor(a.title)) + '</p>' : '') +
          '<div class="alert-time">' + ago(a.time) + ' \u00B7 ' + fmtDate(a.time) + (a.resolved ? ' \u00B7 resolved ' + fmtDate(a.resolvedAt) : '') + '</div>' +
        '</div>' + resolveBtn + '</div>';
    }).join('');
    document.getElementById('alertsEmpty').hidden = list.length > 0;
  }

  /* ---------------------------------------------------------
     RENDER: LOGS
     --------------------------------------------------------- */
  function renderLogs() {
    var search = document.getElementById('logSearch').value.trim().toLowerCase();
    var src = document.getElementById('filterSource').value;
    var risk = document.getElementById('filterRisk').value;

    var list = state.events;
    if (src !== 'all') list = list.filter(function (e) { return e.source === src; });
    if (risk !== 'all') list = list.filter(function (e) { return e.risk === risk; });
    if (search) list = list.filter(function (e) {
      var o = e.origin ? (e.origin.ip + ' ' + e.origin.geo).toLowerCase() : '';
      return e.type.toLowerCase().indexOf(search) !== -1 || e.description.toLowerCase().indexOf(search) !== -1 || o.indexOf(search) !== -1;
    });

    document.querySelector('#fullLogTable tbody').innerHTML = list.map(function (ev) {
      return '<tr><td>' + fmtDate(ev.time) + '</td><td>' + sourceLabel(ev.source) + '</td><td>' +
        escapeHtml(ev.type) + '</td><td class="wrap">' + escapeHtml(ev.description) + '</td><td class="origin">' + originHtml(ev.origin) + '</td><td>' + badgeHtml(ev.risk) + '</td></tr>';
    }).join('');
    document.getElementById('logsEmpty').hidden = list.length > 0;
  }

  /* ---------------------------------------------------------
     RENDER ALL
     --------------------------------------------------------- */
  function renderTrend() {
    var N = 12, W = 5 * 60000, now = Date.now(), b = [], i;
    for (i = 0; i < N; i++) b.push({ safe: 0, warning: 0, threat: 0 });
    state.events.forEach(function (e) {
      var k = N - 1 - Math.floor((now - e.time) / W);
      if (k >= 0 && k < N) b[k][e.risk]++;
    });
    var max = Math.max(4, Math.max.apply(null, b.map(function (x) { return x.safe + x.warning + x.threat; })));
    var bw = 600 / N, svg = '';
    b.forEach(function (x, i) {
      var y = 120;
      ['safe', 'warning', 'threat'].forEach(function (r) {
        var h = x[r] * 100 / max;
        if (!h) return;
        y -= h;
        svg += '<rect x="' + (i * bw + 8) + '" y="' + y + '" width="' + (bw - 16) + '" height="' + Math.max(h - 1, 1) + '" rx="2" fill="var(--' + r + ')"/>';
      });
      if (i % 2 === 1 || i === N - 1) svg += '<text x="' + (i * bw + bw / 2) + '" y="138" text-anchor="middle">' + (i === N - 1 ? 'now' : '-' + ((N - 1 - i) * 5) + 'm') + '</text>';
    });
    document.getElementById('trendChart').innerHTML = svg + '<line class="axis" x1="0" x2="600" y1="120.5" y2="120.5"/>';
  }

  function renderAll() {
    renderTrend();
    renderDashboard();
    renderMobile();
    renderCloud();
    renderAlerts();
    renderLogs();
  }

  /* ---------------------------------------------------------
     NAVIGATION
     --------------------------------------------------------- */
  function switchView(name) {
    document.querySelectorAll('.nav-btn').forEach(function (b) {
      b.classList.toggle('active', b.dataset.view === name);
    });
    document.querySelectorAll('.view').forEach(function (v) {
      v.classList.toggle('active', v.id === 'view-' + name);
    });
    document.getElementById('pageTitle').textContent = TITLES[name] || name;
    document.getElementById('sidebar').classList.remove('open');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  /* ---------------------------------------------------------
     WIRE UP EVENTS
     --------------------------------------------------------- */
  document.querySelectorAll('.nav-btn').forEach(function (b) {
    b.addEventListener('click', function () { switchView(b.dataset.view); });
  });
  document.querySelectorAll('[data-goto]').forEach(function (b) {
    b.addEventListener('click', function () { switchView(b.dataset.goto); });
  });
  document.getElementById('hamburger').addEventListener('click', function () {
    document.getElementById('sidebar').classList.toggle('open');
  });

  // Delegated: any simulator button anywhere in the app (Cloud tab + Simulator tab)
  document.addEventListener('click', function (e) {
    var cloudBtn = e.target.closest('[data-cloud]');
    if (cloudBtn) { simulateCloudEvent(cloudBtn.dataset.cloud); return; }
    var mobileBtn = e.target.closest('[data-mobile]');
    if (mobileBtn) { simulateMobileEvent(mobileBtn.dataset.mobile); return; }
  });

  // Password strength
  var pwInput = document.getElementById('pwInput');
  pwInput.addEventListener('input', function () {
    var r = pwStrength(pwInput.value);
    var fill = document.getElementById('pwMeterFill');
    fill.style.width = (r.pct || 0) + '%';
    fill.style.background = r.risk === 'safe' ? 'var(--safe)' : r.risk === 'warning' ? 'var(--warning)' : r.risk === 'threat' ? 'var(--threat)' : 'var(--border-soft)';
    document.getElementById('pwVerdict').textContent = pwInput.value ? ('Strength: ' + r.label) : '\u2014';
  });
  document.getElementById('pwAudit').addEventListener('click', function () {
    var val = pwInput.value;
    if (!val) { toast('warning', 'No input', 'Type a password to audit first'); return; }
    var r = pwStrength(val);
    addEvent('mobile', 'Password Strength Audit', 'Password audit completed \u2014 rated ' + r.label + ' (length ' + val.length + ')', r.risk);
    toast(r.risk, 'Audit logged', 'Password rated ' + r.label);
    pwInput.value = '';
    document.getElementById('pwMeterFill').style.width = '0%';
    document.getElementById('pwVerdict').textContent = '\u2014';
    save();
    renderAll();
  });

  // Mobile failed login
  document.getElementById('failLoginBtn').addEventListener('click', function () {
    state.mobile.failedLoginCount++;
    var c = state.mobile.failedLoginCount;
    if (c >= 4) {
      addEvent('mobile', 'Repeated Failed Logins', c + ' consecutive failed unlock attempts detected \u2014 possible brute-force on device', 'threat');
      toast('threat', 'Threat detected', 'Repeated failed logins on device');
    } else {
      addEvent('mobile', 'Failed Login', 'Failed unlock attempt #' + c + ' on mobile device', 'warning');
      toast('warning', 'Warning logged', 'Failed login attempt recorded');
    }
    save();
    renderAll();
  });
  document.getElementById('resetLoginBtn').addEventListener('click', function () {
    state.mobile.failedLoginCount = 0;
    save();
    renderAll();
  });

  // App permission table (delegated checkbox changes)
  document.getElementById('appPermTable').addEventListener('change', function (e) {
    var t = e.target;
    if (t.matches('input[type="checkbox"]')) {
      var i = +t.dataset.app, perm = t.dataset.perm;
      state.mobile.apps[i].perms[perm] = t.checked;
      save();
      renderAppPermTable();
    }
  });
  document.getElementById('scanPermsBtn').addEventListener('click', function () {
    var flagged = 0;
    state.mobile.apps.forEach(function (app) {
      var risk = appRisk(app);
      if (risk !== 'safe') {
        flagged++;
        var granted = Object.keys(app.perms).filter(function (k) { return app.perms[k]; }).join(', ');
        addEvent('mobile', 'App Permission Risk', '"' + app.name + '" has excessive permissions granted (' + granted + ')', risk);
      }
    });
    if (flagged === 0) {
      addEvent('mobile', 'App Permission Scan', 'All installed apps have minimal, appropriate permissions', 'safe');
      toast('safe', 'Scan complete', 'No risky permission grants found');
    } else {
      toast('warning', 'Scan complete', flagged + ' app(s) flagged for excessive permissions');
    }
    save();
    renderAll();
  });

  // Unknown app detection
  document.getElementById('scanUnknownBtn').addEventListener('click', function () {
    var found = Math.random() < 0.55;
    var resultEl = document.getElementById('unknownResult');
    if (found) {
      var name = 'com.unknown.sideload' + Math.floor(Math.random() * 900 + 100);
      addEvent('mobile', 'Unknown App Detected', 'Sideloaded application "' + name + '" found outside official app store', 'threat');
      resultEl.textContent = '\u26A0 Unknown app found: ' + name;
      resultEl.style.color = 'var(--threat)';
      toast('threat', 'Threat detected', 'Unknown app installed outside app store');
    } else {
      addEvent('mobile', 'Unknown App Scan', 'No unauthorized or sideloaded applications found', 'safe');
      resultEl.textContent = '\u2713 No unknown apps found';
      resultEl.style.color = 'var(--safe)';
      toast('safe', 'Scan complete', 'Device apps verified clean');
    }
    save();
    renderAll();
  });

  // Public Wi-Fi toggle
  document.getElementById('wifiToggle').addEventListener('change', function (e) {
    state.mobile.publicWifi = e.target.checked;
    if (e.target.checked) {
      addEvent('mobile', 'Public Wi-Fi Connected', 'Device connected to an unencrypted public Wi-Fi network', 'warning');
      toast('warning', 'Warning logged', 'Public Wi-Fi connection is a risk');
    } else {
      addEvent('mobile', 'Network Secured', 'Device disconnected from public network', 'safe');
    }
    save();
    renderAll();
  });

  // Device checklist
  document.getElementById('deviceChecklist').addEventListener('change', function (e) {
    var t = e.target;
    if (t.matches('input[type="checkbox"]')) {
      state.mobile.device[t.dataset.device] = t.checked;
      save();
      renderDeviceChecklist();
    }
  });
  document.getElementById('runDeviceCheckBtn').addEventListener('click', function () {
    var disabled = Object.keys(state.mobile.device).filter(function (k) { return !state.mobile.device[k]; }).map(function (k) { return DEVICE_LABELS[k]; });
    if (disabled.length === 0) {
      addEvent('mobile', 'Device Security Check', 'All device protections are enabled \u2014 screen lock, encryption, OS updates and remote wipe active', 'safe');
      toast('safe', 'Check passed', 'Device fully secured');
    } else if (disabled.length <= 2) {
      addEvent('mobile', 'Device Security Check', 'Device check found ' + disabled.length + ' protection(s) disabled: ' + disabled.join(', '), 'warning');
      toast('warning', 'Check found issues', disabled.length + ' protection(s) disabled');
    } else {
      addEvent('mobile', 'Device Security Check', 'Device check found ' + disabled.length + ' protection(s) disabled: ' + disabled.join(', ') + ' \u2014 device highly vulnerable', 'threat');
      toast('threat', 'Critical', 'Device is highly vulnerable');
    }
    save();
    renderAll();
  });

  // Alerts: resolve + show-resolved toggle
  document.getElementById('alertList').addEventListener('click', function (e) {
    var btn = e.target.closest('[data-resolve]');
    if (!btn) return;
    var a = state.alerts.find(function (al) { return al.id === btn.dataset.resolve; });
    if (a) {
      a.resolved = true;
      a.resolvedAt = Date.now();
      save();
      toast('safe', 'Alert resolved', a.title);
      renderAll();
    }
  });
  document.getElementById('showResolvedToggle').addEventListener('change', renderAlerts);

  // Logs: search + filters
  document.getElementById('logSearch').addEventListener('input', renderLogs);
  document.getElementById('filterSource').addEventListener('change', renderLogs);
  document.getElementById('filterRisk').addEventListener('change', renderLogs);
  document.getElementById('clearLogsBtn').addEventListener('click', function () {
    if (!confirm('Clear all activity logs and alerts? This cannot be undone.')) return;
    state.events = [];
    state.alerts = [];
    save();
    toast('safe', 'Logs cleared', 'All activity has been wiped');
    renderAll();
  });

  document.getElementById('liveToggle').addEventListener('change', function (e) {
    setLive(e.target.checked);
    toast('safe', e.target.checked ? 'Live monitoring on' : 'Live monitoring off',
      e.target.checked ? 'Background activity will be logged as it happens' : 'Background activity stopped');
  });

  document.getElementById('resolveAllBtn').addEventListener('click', function () {
    var n = 0;
    state.alerts.forEach(function (a) { if (!a.resolved) { a.resolved = true; a.resolvedAt = Date.now(); n++; } });
    if (!n) { toast('warning', 'Nothing to resolve', 'There are no active alerts'); return; }
    save();
    toast('safe', 'Alerts resolved', n + ' alert(s) closed');
    renderAll();
  });

  document.getElementById('exportLogsBtn').addEventListener('click', function () {
    var rows = [['time', 'source', 'event', 'description', 'risk', 'ip', 'location', 'device']];
    state.events.forEach(function (e) {
      var o = e.origin || {};
      rows.push([new Date(e.time).toISOString(), e.source, e.type, e.description, e.risk, o.ip || '', o.geo || '', o.device || '']);
    });
    var csv = rows.map(function (r) {
      return r.map(function (c) { return '"' + String(c).replace(/"/g, '""') + '"'; }).join(',');
    }).join('\n');
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'vigil-logs-' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('safe', 'Logs exported', state.events.length + ' events saved as CSV');
  });

  setInterval(renderTrend, 30000);

  // Full simulation reset
  document.getElementById('resetAllBtn').addEventListener('click', function () {
    if (!confirm('Factory reset the entire simulation? All events, alerts and counters will be wiped.')) return;
    state = defaultState();
    save();
    toast('safe', 'Simulation reset', 'Starting fresh');
    renderAll();
  });

  /* ---------------------------------------------------------
     CLOCK
     --------------------------------------------------------- */
  function tickClock() {
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();
  }
  tickClock();
  setInterval(tickClock, 1000);

  /* ---------------------------------------------------------
     INIT
     --------------------------------------------------------- */
  renderAll();

})();
