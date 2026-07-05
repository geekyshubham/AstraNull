//#region \0rolldown/runtime.js
var e = Object.create, t = Object.defineProperty, n = Object.getOwnPropertyDescriptor, r = Object.getOwnPropertyNames, i = Object.getPrototypeOf, a = Object.prototype.hasOwnProperty, o = (e, t) => () => (t || (e((t = { exports: {} }).exports, t), e = null), t.exports), s = (e, i, o, s) => {
  if (i && typeof i == "object" || typeof i == "function") for (var c = r(i), l = 0, u = c.length, d; l < u; l++) d = c[l], !a.call(e, d) && d !== o && t(e, d, {
    get: ((e) => i[e]).bind(null, d),
    enumerable: !(s = n(i, d)) || s.enumerable
  });
  return e;
}, c = (n, r, a) => (a = n == null ? {} : e(i(n)), s(r || !n || !n.__esModule ? t(a, "default", {
  value: n,
  enumerable: !0
}) : a, n)), l = /* @__PURE__ */ o(((e) => {
  var t = Symbol.for("react.transitional.element"), n = Symbol.for("react.portal"), r = Symbol.for("react.fragment"), i = Symbol.for("react.strict_mode"), a = Symbol.for("react.profiler"), o = Symbol.for("react.consumer"), s = Symbol.for("react.context"), c = Symbol.for("react.forward_ref"), l = Symbol.for("react.suspense"), u = Symbol.for("react.memo"), d = Symbol.for("react.lazy"), f = Symbol.for("react.activity"), p = Symbol.iterator;
  function m(e) {
    return typeof e != "object" || !e ? null : (e = p && e[p] || e["@@iterator"], typeof e == "function" ? e : null);
  }
  var h = {
    isMounted: function() {
      return !1;
    },
    enqueueForceUpdate: function() {},
    enqueueReplaceState: function() {},
    enqueueSetState: function() {}
  }, g = Object.assign, _ = {};
  function v(e, t, n) {
    this.props = e, this.context = t, this.refs = _, this.updater = n || h;
  }
  v.prototype.isReactComponent = {}, v.prototype.setState = function(e, t) {
    if (typeof e != "object" && typeof e != "function" && e != null) throw Error("takes an object of state variables to update or a function which returns an object of state variables.");
    this.updater.enqueueSetState(this, e, t, "setState");
  }, v.prototype.forceUpdate = function(e) {
    this.updater.enqueueForceUpdate(this, e, "forceUpdate");
  };
  function y() {}
  y.prototype = v.prototype;
  function b(e, t, n) {
    this.props = e, this.context = t, this.refs = _, this.updater = n || h;
  }
  var x = b.prototype = new y();
  x.constructor = b, g(x, v.prototype), x.isPureReactComponent = !0;
  var S = Array.isArray;
  function C() {}
  var w = {
    H: null,
    A: null,
    T: null,
    S: null
  }, T = Object.prototype.hasOwnProperty;
  function E(e, n, r) {
    var i = r.ref;
    return {
      $$typeof: t,
      type: e,
      key: n,
      ref: i === void 0 ? null : i,
      props: r
    };
  }
  function D(e, t) {
    return E(e.type, t, e.props);
  }
  function O(e) {
    return typeof e == "object" && !!e && e.$$typeof === t;
  }
  function ee(e) {
    var t = {
      "=": "=0",
      ":": "=2"
    };
    return "$" + e.replace(/[=:]/g, function(e) {
      return t[e];
    });
  }
  var te = /\/+/g;
  function ne(e, t) {
    return typeof e == "object" && e && e.key != null ? ee("" + e.key) : t.toString(36);
  }
  function re(e) {
    switch (e.status) {
      case "fulfilled": return e.value;
      case "rejected": throw e.reason;
      default: switch (typeof e.status == "string" ? e.then(C, C) : (e.status = "pending", e.then(function(t) {
        e.status === "pending" && (e.status = "fulfilled", e.value = t);
      }, function(t) {
        e.status === "pending" && (e.status = "rejected", e.reason = t);
      })), e.status) {
        case "fulfilled": return e.value;
        case "rejected": throw e.reason;
      }
    }
    throw e;
  }
  function ie(e, r, i, a, o) {
    var s = typeof e;
    (s === "undefined" || s === "boolean") && (e = null);
    var c = !1;
    if (e === null) c = !0;
    else switch (s) {
      case "bigint":
      case "string":
      case "number":
        c = !0;
        break;
      case "object": switch (e.$$typeof) {
        case t:
        case n:
          c = !0;
          break;
        case d: return c = e._init, ie(c(e._payload), r, i, a, o);
      }
    }
    if (c) return o = o(e), c = a === "" ? "." + ne(e, 0) : a, S(o) ? (i = "", c != null && (i = c.replace(te, "$&/") + "/"), ie(o, r, i, "", function(e) {
      return e;
    })) : o != null && (O(o) && (o = D(o, i + (o.key == null || e && e.key === o.key ? "" : ("" + o.key).replace(te, "$&/") + "/") + c)), r.push(o)), 1;
    c = 0;
    var l = a === "" ? "." : a + ":";
    if (S(e)) for (var u = 0; u < e.length; u++) a = e[u], s = l + ne(a, u), c += ie(a, r, i, s, o);
    else if (u = m(e), typeof u == "function") for (e = u.call(e), u = 0; !(a = e.next()).done;) a = a.value, s = l + ne(a, u++), c += ie(a, r, i, s, o);
    else if (s === "object") {
      if (typeof e.then == "function") return ie(re(e), r, i, a, o);
      throw r = String(e), Error("Objects are not valid as a React child (found: " + (r === "[object Object]" ? "object with keys {" + Object.keys(e).join(", ") + "}" : r) + "). If you meant to render a collection of children, use an array instead.");
    }
    return c;
  }
  function ae(e, t, n) {
    if (e == null) return e;
    var r = [], i = 0;
    return ie(e, r, "", "", function(e) {
      return t.call(n, e, i++);
    }), r;
  }
  function oe(e) {
    if (e._status === -1) {
      var t = e._result;
      t = t(), t.then(function(t) {
        (e._status === 0 || e._status === -1) && (e._status = 1, e._result = t);
      }, function(t) {
        (e._status === 0 || e._status === -1) && (e._status = 2, e._result = t);
      }), e._status === -1 && (e._status = 0, e._result = t);
    }
    if (e._status === 1) return e._result.default;
    throw e._result;
  }
  var k = typeof reportError == "function" ? reportError : function(e) {
    if (typeof window == "object" && typeof window.ErrorEvent == "function") {
      var t = new window.ErrorEvent("error", {
        bubbles: !0,
        cancelable: !0,
        message: typeof e == "object" && e && typeof e.message == "string" ? String(e.message) : String(e),
        error: e
      });
      if (!window.dispatchEvent(t)) return;
    } else if (typeof process == "object" && typeof process.emit == "function") {
      process.emit("uncaughtException", e);
      return;
    }
    console.error(e);
  }, A = {
    map: ae,
    forEach: function(e, t, n) {
      ae(e, function() {
        t.apply(this, arguments);
      }, n);
    },
    count: function(e) {
      var t = 0;
      return ae(e, function() {
        t++;
      }), t;
    },
    toArray: function(e) {
      return ae(e, function(e) {
        return e;
      }) || [];
    },
    only: function(e) {
      if (!O(e)) throw Error("React.Children.only expected to receive a single React element child.");
      return e;
    }
  };
  e.Activity = f, e.Children = A, e.Component = v, e.Fragment = r, e.Profiler = a, e.PureComponent = b, e.StrictMode = i, e.Suspense = l, e.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE = w, e.__COMPILER_RUNTIME = {
    __proto__: null,
    c: function(e) {
      return w.H.useMemoCache(e);
    }
  }, e.cache = function(e) {
    return function() {
      return e.apply(null, arguments);
    };
  }, e.cacheSignal = function() {
    return null;
  }, e.cloneElement = function(e, t, n) {
    if (e == null) throw Error("The argument must be a React element, but you passed " + e + ".");
    var r = g({}, e.props), i = e.key;
    if (t != null) for (a in t.key !== void 0 && (i = "" + t.key), t) !T.call(t, a) || a === "key" || a === "__self" || a === "__source" || a === "ref" && t.ref === void 0 || (r[a] = t[a]);
    var a = arguments.length - 2;
    if (a === 1) r.children = n;
    else if (1 < a) {
      for (var o = Array(a), s = 0; s < a; s++) o[s] = arguments[s + 2];
      r.children = o;
    }
    return E(e.type, i, r);
  }, e.createContext = function(e) {
    return e = {
      $$typeof: s,
      _currentValue: e,
      _currentValue2: e,
      _threadCount: 0,
      Provider: null,
      Consumer: null
    }, e.Provider = e, e.Consumer = {
      $$typeof: o,
      _context: e
    }, e;
  }, e.createElement = function(e, t, n) {
    var r, i = {}, a = null;
    if (t != null) for (r in t.key !== void 0 && (a = "" + t.key), t) T.call(t, r) && r !== "key" && r !== "__self" && r !== "__source" && (i[r] = t[r]);
    var o = arguments.length - 2;
    if (o === 1) i.children = n;
    else if (1 < o) {
      for (var s = Array(o), c = 0; c < o; c++) s[c] = arguments[c + 2];
      i.children = s;
    }
    if (e && e.defaultProps) for (r in o = e.defaultProps, o) i[r] === void 0 && (i[r] = o[r]);
    return E(e, a, i);
  }, e.createRef = function() {
    return { current: null };
  }, e.forwardRef = function(e) {
    return {
      $$typeof: c,
      render: e
    };
  }, e.isValidElement = O, e.lazy = function(e) {
    return {
      $$typeof: d,
      _payload: {
        _status: -1,
        _result: e
      },
      _init: oe
    };
  }, e.memo = function(e, t) {
    return {
      $$typeof: u,
      type: e,
      compare: t === void 0 ? null : t
    };
  }, e.startTransition = function(e) {
    var t = w.T, n = {};
    w.T = n;
    try {
      var r = e(), i = w.S;
      i !== null && i(n, r), typeof r == "object" && r && typeof r.then == "function" && r.then(C, k);
    } catch (e) {
      k(e);
    } finally {
      t !== null && n.types !== null && (t.types = n.types), w.T = t;
    }
  }, e.unstable_useCacheRefresh = function() {
    return w.H.useCacheRefresh();
  }, e.use = function(e) {
    return w.H.use(e);
  }, e.useActionState = function(e, t, n) {
    return w.H.useActionState(e, t, n);
  }, e.useCallback = function(e, t) {
    return w.H.useCallback(e, t);
  }, e.useContext = function(e) {
    return w.H.useContext(e);
  }, e.useDebugValue = function() {}, e.useDeferredValue = function(e, t) {
    return w.H.useDeferredValue(e, t);
  }, e.useEffect = function(e, t) {
    return w.H.useEffect(e, t);
  }, e.useEffectEvent = function(e) {
    return w.H.useEffectEvent(e);
  }, e.useId = function() {
    return w.H.useId();
  }, e.useImperativeHandle = function(e, t, n) {
    return w.H.useImperativeHandle(e, t, n);
  }, e.useInsertionEffect = function(e, t) {
    return w.H.useInsertionEffect(e, t);
  }, e.useLayoutEffect = function(e, t) {
    return w.H.useLayoutEffect(e, t);
  }, e.useMemo = function(e, t) {
    return w.H.useMemo(e, t);
  }, e.useOptimistic = function(e, t) {
    return w.H.useOptimistic(e, t);
  }, e.useReducer = function(e, t, n) {
    return w.H.useReducer(e, t, n);
  }, e.useRef = function(e) {
    return w.H.useRef(e);
  }, e.useState = function(e) {
    return w.H.useState(e);
  }, e.useSyncExternalStore = function(e, t, n) {
    return w.H.useSyncExternalStore(e, t, n);
  }, e.useTransition = function() {
    return w.H.useTransition();
  }, e.version = "19.2.7";
})), u = /* @__PURE__ */ o(((e, t) => {
  t.exports = l();
})), d = /* @__PURE__ */ o(((e) => {
  function t(e, t) {
    var n = e.length;
    e.push(t);
    a: for (; 0 < n;) {
      var r = n - 1 >>> 1, a = e[r];
      if (0 < i(a, t)) e[r] = t, e[n] = a, n = r;
      else break a;
    }
  }
  function n(e) {
    return e.length === 0 ? null : e[0];
  }
  function r(e) {
    if (e.length === 0) return null;
    var t = e[0], n = e.pop();
    if (n !== t) {
      e[0] = n;
      a: for (var r = 0, a = e.length, o = a >>> 1; r < o;) {
        var s = 2 * (r + 1) - 1, c = e[s], l = s + 1, u = e[l];
        if (0 > i(c, n)) l < a && 0 > i(u, c) ? (e[r] = u, e[l] = n, r = l) : (e[r] = c, e[s] = n, r = s);
        else if (l < a && 0 > i(u, n)) e[r] = u, e[l] = n, r = l;
        else break a;
      }
    }
    return t;
  }
  function i(e, t) {
    var n = e.sortIndex - t.sortIndex;
    return n === 0 ? e.id - t.id : n;
  }
  if (e.unstable_now = void 0, typeof performance == "object" && typeof performance.now == "function") {
    var a = performance;
    e.unstable_now = function() {
      return a.now();
    };
  } else {
    var o = Date, s = o.now();
    e.unstable_now = function() {
      return o.now() - s;
    };
  }
  var c = [], l = [], u = 1, d = null, f = 3, p = !1, m = !1, h = !1, g = !1, _ = typeof setTimeout == "function" ? setTimeout : null, v = typeof clearTimeout == "function" ? clearTimeout : null, y = typeof setImmediate < "u" ? setImmediate : null;
  function b(e) {
    for (var i = n(l); i !== null;) {
      if (i.callback === null) r(l);
      else if (i.startTime <= e) r(l), i.sortIndex = i.expirationTime, t(c, i);
      else break;
      i = n(l);
    }
  }
  function x(e) {
    if (h = !1, b(e), !m) if (n(c) !== null) m = !0, S || (S = !0, O());
    else {
      var t = n(l);
      t !== null && ne(x, t.startTime - e);
    }
  }
  var S = !1, C = -1, w = 5, T = -1;
  function E() {
    return g ? !0 : !(e.unstable_now() - T < w);
  }
  function D() {
    if (g = !1, S) {
      var t = e.unstable_now();
      T = t;
      var i = !0;
      try {
        a: {
          m = !1, h && (h = !1, v(C), C = -1), p = !0;
          var a = f;
          try {
            b: {
              for (b(t), d = n(c); d !== null && !(d.expirationTime > t && E());) {
                var o = d.callback;
                if (typeof o == "function") {
                  d.callback = null, f = d.priorityLevel;
                  var s = o(d.expirationTime <= t);
                  if (t = e.unstable_now(), typeof s == "function") {
                    d.callback = s, b(t), i = !0;
                    break b;
                  }
                  d === n(c) && r(c), b(t);
                } else r(c);
                d = n(c);
              }
              if (d !== null) i = !0;
              else {
                var u = n(l);
                u !== null && ne(x, u.startTime - t), i = !1;
              }
            }
            break a;
          } finally {
            d = null, f = a, p = !1;
          }
          i = void 0;
        }
      } finally {
        i ? O() : S = !1;
      }
    }
  }
  var O;
  if (typeof y == "function") O = function() {
    y(D);
  };
  else if (typeof MessageChannel < "u") {
    var ee = new MessageChannel(), te = ee.port2;
    ee.port1.onmessage = D, O = function() {
      te.postMessage(null);
    };
  } else O = function() {
    _(D, 0);
  };
  function ne(t, n) {
    C = _(function() {
      t(e.unstable_now());
    }, n);
  }
  e.unstable_IdlePriority = 5, e.unstable_ImmediatePriority = 1, e.unstable_LowPriority = 4, e.unstable_NormalPriority = 3, e.unstable_Profiling = null, e.unstable_UserBlockingPriority = 2, e.unstable_cancelCallback = function(e) {
    e.callback = null;
  }, e.unstable_forceFrameRate = function(e) {
    0 > e || 125 < e ? console.error("forceFrameRate takes a positive int between 0 and 125, forcing frame rates higher than 125 fps is not supported") : w = 0 < e ? Math.floor(1e3 / e) : 5;
  }, e.unstable_getCurrentPriorityLevel = function() {
    return f;
  }, e.unstable_next = function(e) {
    switch (f) {
      case 1:
      case 2:
      case 3:
        var t = 3;
        break;
      default: t = f;
    }
    var n = f;
    f = t;
    try {
      return e();
    } finally {
      f = n;
    }
  }, e.unstable_requestPaint = function() {
    g = !0;
  }, e.unstable_runWithPriority = function(e, t) {
    switch (e) {
      case 1:
      case 2:
      case 3:
      case 4:
      case 5: break;
      default: e = 3;
    }
    var n = f;
    f = e;
    try {
      return t();
    } finally {
      f = n;
    }
  }, e.unstable_scheduleCallback = function(r, i, a) {
    var o = e.unstable_now();
    switch (typeof a == "object" && a ? (a = a.delay, a = typeof a == "number" && 0 < a ? o + a : o) : a = o, r) {
      case 1:
        var s = -1;
        break;
      case 2:
        s = 250;
        break;
      case 5:
        s = 1073741823;
        break;
      case 4:
        s = 1e4;
        break;
      default: s = 5e3;
    }
    return s = a + s, r = {
      id: u++,
      callback: i,
      priorityLevel: r,
      startTime: a,
      expirationTime: s,
      sortIndex: -1
    }, a > o ? (r.sortIndex = a, t(l, r), n(c) === null && r === n(l) && (h ? (v(C), C = -1) : h = !0, ne(x, a - o))) : (r.sortIndex = s, t(c, r), m || p || (m = !0, S || (S = !0, O()))), r;
  }, e.unstable_shouldYield = E, e.unstable_wrapCallback = function(e) {
    var t = f;
    return function() {
      var n = f;
      f = t;
      try {
        return e.apply(this, arguments);
      } finally {
        f = n;
      }
    };
  };
})), f = /* @__PURE__ */ o(((e, t) => {
  t.exports = d();
})), p = /* @__PURE__ */ o(((e) => {
  var t = u();
  function n(e) {
    var t = "https://react.dev/errors/" + e;
    if (1 < arguments.length) {
      t += "?args[]=" + encodeURIComponent(arguments[1]);
      for (var n = 2; n < arguments.length; n++) t += "&args[]=" + encodeURIComponent(arguments[n]);
    }
    return "Minified React error #" + e + "; visit " + t + " for the full message or use the non-minified dev environment for full errors and additional helpful warnings.";
  }
  function r() {}
  var i = {
    d: {
      f: r,
      r: function() {
        throw Error(n(522));
      },
      D: r,
      C: r,
      L: r,
      m: r,
      X: r,
      S: r,
      M: r
    },
    p: 0,
    findDOMNode: null
  }, a = Symbol.for("react.portal");
  function o(e, t, n) {
    var r = 3 < arguments.length && arguments[3] !== void 0 ? arguments[3] : null;
    return {
      $$typeof: a,
      key: r == null ? null : "" + r,
      children: e,
      containerInfo: t,
      implementation: n
    };
  }
  var s = t.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;
  function c(e, t) {
    if (e === "font") return "";
    if (typeof t == "string") return t === "use-credentials" ? t : "";
  }
  e.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE = i, e.createPortal = function(e, t) {
    var r = 2 < arguments.length && arguments[2] !== void 0 ? arguments[2] : null;
    if (!t || t.nodeType !== 1 && t.nodeType !== 9 && t.nodeType !== 11) throw Error(n(299));
    return o(e, t, null, r);
  }, e.flushSync = function(e) {
    var t = s.T, n = i.p;
    try {
      if (s.T = null, i.p = 2, e) return e();
    } finally {
      s.T = t, i.p = n, i.d.f();
    }
  }, e.preconnect = function(e, t) {
    typeof e == "string" && (t ? (t = t.crossOrigin, t = typeof t == "string" ? t === "use-credentials" ? t : "" : void 0) : t = null, i.d.C(e, t));
  }, e.prefetchDNS = function(e) {
    typeof e == "string" && i.d.D(e);
  }, e.preinit = function(e, t) {
    if (typeof e == "string" && t && typeof t.as == "string") {
      var n = t.as, r = c(n, t.crossOrigin), a = typeof t.integrity == "string" ? t.integrity : void 0, o = typeof t.fetchPriority == "string" ? t.fetchPriority : void 0;
      n === "style" ? i.d.S(e, typeof t.precedence == "string" ? t.precedence : void 0, {
        crossOrigin: r,
        integrity: a,
        fetchPriority: o
      }) : n === "script" && i.d.X(e, {
        crossOrigin: r,
        integrity: a,
        fetchPriority: o,
        nonce: typeof t.nonce == "string" ? t.nonce : void 0
      });
    }
  }, e.preinitModule = function(e, t) {
    if (typeof e == "string") if (typeof t == "object" && t) {
      if (t.as == null || t.as === "script") {
        var n = c(t.as, t.crossOrigin);
        i.d.M(e, {
          crossOrigin: n,
          integrity: typeof t.integrity == "string" ? t.integrity : void 0,
          nonce: typeof t.nonce == "string" ? t.nonce : void 0
        });
      }
    } else t ?? i.d.M(e);
  }, e.preload = function(e, t) {
    if (typeof e == "string" && typeof t == "object" && t && typeof t.as == "string") {
      var n = t.as, r = c(n, t.crossOrigin);
      i.d.L(e, n, {
        crossOrigin: r,
        integrity: typeof t.integrity == "string" ? t.integrity : void 0,
        nonce: typeof t.nonce == "string" ? t.nonce : void 0,
        type: typeof t.type == "string" ? t.type : void 0,
        fetchPriority: typeof t.fetchPriority == "string" ? t.fetchPriority : void 0,
        referrerPolicy: typeof t.referrerPolicy == "string" ? t.referrerPolicy : void 0,
        imageSrcSet: typeof t.imageSrcSet == "string" ? t.imageSrcSet : void 0,
        imageSizes: typeof t.imageSizes == "string" ? t.imageSizes : void 0,
        media: typeof t.media == "string" ? t.media : void 0
      });
    }
  }, e.preloadModule = function(e, t) {
    if (typeof e == "string") if (t) {
      var n = c(t.as, t.crossOrigin);
      i.d.m(e, {
        as: typeof t.as == "string" && t.as !== "script" ? t.as : void 0,
        crossOrigin: n,
        integrity: typeof t.integrity == "string" ? t.integrity : void 0
      });
    } else i.d.m(e);
  }, e.requestFormReset = function(e) {
    i.d.r(e);
  }, e.unstable_batchedUpdates = function(e, t) {
    return e(t);
  }, e.useFormState = function(e, t, n) {
    return s.H.useFormState(e, t, n);
  }, e.useFormStatus = function() {
    return s.H.useHostTransitionStatus();
  }, e.version = "19.2.7";
})), m = /* @__PURE__ */ o(((e, t) => {
  function n() {
    if (!(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ > "u" || typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE != "function")) try {
      __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(n);
    } catch (e) {
      console.error(e);
    }
  }
  n(), t.exports = p();
})), h = /* @__PURE__ */ o(((e) => {
  var t = f(), n = u(), r = m();
  function i(e) {
    var t = "https://react.dev/errors/" + e;
    if (1 < arguments.length) {
      t += "?args[]=" + encodeURIComponent(arguments[1]);
      for (var n = 2; n < arguments.length; n++) t += "&args[]=" + encodeURIComponent(arguments[n]);
    }
    return "Minified React error #" + e + "; visit " + t + " for the full message or use the non-minified dev environment for full errors and additional helpful warnings.";
  }
  function a(e) {
    return !(!e || e.nodeType !== 1 && e.nodeType !== 9 && e.nodeType !== 11);
  }
  function o(e) {
    var t = e, n = e;
    if (e.alternate) for (; t.return;) t = t.return;
    else {
      e = t;
      do
        t = e, t.flags & 4098 && (n = t.return), e = t.return;
      while (e);
    }
    return t.tag === 3 ? n : null;
  }
  function s(e) {
    if (e.tag === 13) {
      var t = e.memoizedState;
      if (t === null && (e = e.alternate, e !== null && (t = e.memoizedState)), t !== null) return t.dehydrated;
    }
    return null;
  }
  function c(e) {
    if (e.tag === 31) {
      var t = e.memoizedState;
      if (t === null && (e = e.alternate, e !== null && (t = e.memoizedState)), t !== null) return t.dehydrated;
    }
    return null;
  }
  function l(e) {
    if (o(e) !== e) throw Error(i(188));
  }
  function d(e) {
    var t = e.alternate;
    if (!t) {
      if (t = o(e), t === null) throw Error(i(188));
      return t === e ? e : null;
    }
    for (var n = e, r = t;;) {
      var a = n.return;
      if (a === null) break;
      var s = a.alternate;
      if (s === null) {
        if (r = a.return, r !== null) {
          n = r;
          continue;
        }
        break;
      }
      if (a.child === s.child) {
        for (s = a.child; s;) {
          if (s === n) return l(a), e;
          if (s === r) return l(a), t;
          s = s.sibling;
        }
        throw Error(i(188));
      }
      if (n.return !== r.return) n = a, r = s;
      else {
        for (var c = !1, u = a.child; u;) {
          if (u === n) {
            c = !0, n = a, r = s;
            break;
          }
          if (u === r) {
            c = !0, r = a, n = s;
            break;
          }
          u = u.sibling;
        }
        if (!c) {
          for (u = s.child; u;) {
            if (u === n) {
              c = !0, n = s, r = a;
              break;
            }
            if (u === r) {
              c = !0, r = s, n = a;
              break;
            }
            u = u.sibling;
          }
          if (!c) throw Error(i(189));
        }
      }
      if (n.alternate !== r) throw Error(i(190));
    }
    if (n.tag !== 3) throw Error(i(188));
    return n.stateNode.current === n ? e : t;
  }
  function p(e) {
    var t = e.tag;
    if (t === 5 || t === 26 || t === 27 || t === 6) return e;
    for (e = e.child; e !== null;) {
      if (t = p(e), t !== null) return t;
      e = e.sibling;
    }
    return null;
  }
  var h = Object.assign, g = Symbol.for("react.element"), _ = Symbol.for("react.transitional.element"), v = Symbol.for("react.portal"), y = Symbol.for("react.fragment"), b = Symbol.for("react.strict_mode"), x = Symbol.for("react.profiler"), S = Symbol.for("react.consumer"), C = Symbol.for("react.context"), w = Symbol.for("react.forward_ref"), T = Symbol.for("react.suspense"), E = Symbol.for("react.suspense_list"), D = Symbol.for("react.memo"), O = Symbol.for("react.lazy"), ee = Symbol.for("react.activity"), te = Symbol.for("react.memo_cache_sentinel"), ne = Symbol.iterator;
  function re(e) {
    return typeof e != "object" || !e ? null : (e = ne && e[ne] || e["@@iterator"], typeof e == "function" ? e : null);
  }
  var ie = Symbol.for("react.client.reference");
  function ae(e) {
    if (e == null) return null;
    if (typeof e == "function") return e.$$typeof === ie ? null : e.displayName || e.name || null;
    if (typeof e == "string") return e;
    switch (e) {
      case y: return "Fragment";
      case x: return "Profiler";
      case b: return "StrictMode";
      case T: return "Suspense";
      case E: return "SuspenseList";
      case ee: return "Activity";
    }
    if (typeof e == "object") switch (e.$$typeof) {
      case v: return "Portal";
      case C: return e.displayName || "Context";
      case S: return (e._context.displayName || "Context") + ".Consumer";
      case w:
        var t = e.render;
        return e = e.displayName, e ||= (e = t.displayName || t.name || "", e === "" ? "ForwardRef" : "ForwardRef(" + e + ")"), e;
      case D: return t = e.displayName || null, t === null ? ae(e.type) || "Memo" : t;
      case O:
        t = e._payload, e = e._init;
        try {
          return ae(e(t));
        } catch {}
    }
    return null;
  }
  var oe = Array.isArray, k = n.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE, A = r.__DOM_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE, se = {
    pending: !1,
    data: null,
    method: null,
    action: null
  }, ce = [], j = -1;
  function le(e) {
    return { current: e };
  }
  function ue(e) {
    0 > j || (e.current = ce[j], ce[j] = null, j--);
  }
  function M(e, t) {
    j++, ce[j] = e.current, e.current = t;
  }
  var de = le(null), fe = le(null), pe = le(null), me = le(null);
  function he(e, t) {
    switch (M(pe, t), M(fe, e), M(de, null), t.nodeType) {
      case 9:
      case 11:
        e = (e = t.documentElement) && (e = e.namespaceURI) ? Vd(e) : 0;
        break;
      default: if (e = t.tagName, t = t.namespaceURI) t = Vd(t), e = Hd(t, e);
      else switch (e) {
        case "svg":
          e = 1;
          break;
        case "math":
          e = 2;
          break;
        default: e = 0;
      }
    }
    ue(de), M(de, e);
  }
  function ge() {
    ue(de), ue(fe), ue(pe);
  }
  function _e(e) {
    e.memoizedState !== null && M(me, e);
    var t = de.current, n = Hd(t, e.type);
    t !== n && (M(fe, e), M(de, n));
  }
  function ve(e) {
    fe.current === e && (ue(de), ue(fe)), me.current === e && (ue(me), Qf._currentValue = se);
  }
  var ye, be;
  function xe(e) {
    if (ye === void 0) try {
      throw Error();
    } catch (e) {
      var t = e.stack.trim().match(/\n( *(at )?)/);
      ye = t && t[1] || "", be = -1 < e.stack.indexOf("\n    at") ? " (<anonymous>)" : -1 < e.stack.indexOf("@") ? "@unknown:0:0" : "";
    }
    return "\n" + ye + e + be;
  }
  var Se = !1;
  function Ce(e, t) {
    if (!e || Se) return "";
    Se = !0;
    var n = Error.prepareStackTrace;
    Error.prepareStackTrace = void 0;
    try {
      var r = { DetermineComponentFrameRoot: function() {
        try {
          if (t) {
            var n = function() {
              throw Error();
            };
            if (Object.defineProperty(n.prototype, "props", { set: function() {
              throw Error();
            } }), typeof Reflect == "object" && Reflect.construct) {
              try {
                Reflect.construct(n, []);
              } catch (e) {
                var r = e;
              }
              Reflect.construct(e, [], n);
            } else {
              try {
                n.call();
              } catch (e) {
                r = e;
              }
              e.call(n.prototype);
            }
          } else {
            try {
              throw Error();
            } catch (e) {
              r = e;
            }
            (n = e()) && typeof n.catch == "function" && n.catch(function() {});
          }
        } catch (e) {
          if (e && r && typeof e.stack == "string") return [e.stack, r.stack];
        }
        return [null, null];
      } };
      r.DetermineComponentFrameRoot.displayName = "DetermineComponentFrameRoot";
      var i = Object.getOwnPropertyDescriptor(r.DetermineComponentFrameRoot, "name");
      i && i.configurable && Object.defineProperty(r.DetermineComponentFrameRoot, "name", { value: "DetermineComponentFrameRoot" });
      var a = r.DetermineComponentFrameRoot(), o = a[0], s = a[1];
      if (o && s) {
        var c = o.split("\n"), l = s.split("\n");
        for (i = r = 0; r < c.length && !c[r].includes("DetermineComponentFrameRoot");) r++;
        for (; i < l.length && !l[i].includes("DetermineComponentFrameRoot");) i++;
        if (r === c.length || i === l.length) for (r = c.length - 1, i = l.length - 1; 1 <= r && 0 <= i && c[r] !== l[i];) i--;
        for (; 1 <= r && 0 <= i; r--, i--) if (c[r] !== l[i]) {
          if (r !== 1 || i !== 1) do
            if (r--, i--, 0 > i || c[r] !== l[i]) {
              var u = "\n" + c[r].replace(" at new ", " at ");
              return e.displayName && u.includes("<anonymous>") && (u = u.replace("<anonymous>", e.displayName)), u;
            }
          while (1 <= r && 0 <= i);
          break;
        }
      }
    } finally {
      Se = !1, Error.prepareStackTrace = n;
    }
    return (n = e ? e.displayName || e.name : "") ? xe(n) : "";
  }
  function we(e, t) {
    switch (e.tag) {
      case 26:
      case 27:
      case 5: return xe(e.type);
      case 16: return xe("Lazy");
      case 13: return e.child !== t && t !== null ? xe("Suspense Fallback") : xe("Suspense");
      case 19: return xe("SuspenseList");
      case 0:
      case 15: return Ce(e.type, !1);
      case 11: return Ce(e.type.render, !1);
      case 1: return Ce(e.type, !0);
      case 31: return xe("Activity");
      default: return "";
    }
  }
  function Te(e) {
    try {
      var t = "", n = null;
      do
        t += we(e, n), n = e, e = e.return;
      while (e);
      return t;
    } catch (e) {
      return "\nError generating stack: " + e.message + "\n" + e.stack;
    }
  }
  var N = Object.prototype.hasOwnProperty, Ee = t.unstable_scheduleCallback, De = t.unstable_cancelCallback, Oe = t.unstable_shouldYield, ke = t.unstable_requestPaint, Ae = t.unstable_now, je = t.unstable_getCurrentPriorityLevel, Me = t.unstable_ImmediatePriority, Ne = t.unstable_UserBlockingPriority, Pe = t.unstable_NormalPriority, Fe = t.unstable_LowPriority, Ie = t.unstable_IdlePriority, Le = t.log, Re = t.unstable_setDisableYieldValue, ze = null, Be = null;
  function Ve(e) {
    if (typeof Le == "function" && Re(e), Be && typeof Be.setStrictMode == "function") try {
      Be.setStrictMode(ze, e);
    } catch {}
  }
  var He = Math.clz32 ? Math.clz32 : Ge, Ue = Math.log, We = Math.LN2;
  function Ge(e) {
    return e >>>= 0, e === 0 ? 32 : 31 - (Ue(e) / We | 0) | 0;
  }
  var Ke = 256, qe = 262144, Je = 4194304;
  function Ye(e) {
    var t = e & 42;
    if (t !== 0) return t;
    switch (e & -e) {
      case 1: return 1;
      case 2: return 2;
      case 4: return 4;
      case 8: return 8;
      case 16: return 16;
      case 32: return 32;
      case 64: return 64;
      case 128: return 128;
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072: return e & 261888;
      case 262144:
      case 524288:
      case 1048576:
      case 2097152: return e & 3932160;
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432: return e & 62914560;
      case 67108864: return 67108864;
      case 134217728: return 134217728;
      case 268435456: return 268435456;
      case 536870912: return 536870912;
      case 1073741824: return 0;
      default: return e;
    }
  }
  function Xe(e, t, n) {
    var r = e.pendingLanes;
    if (r === 0) return 0;
    var i = 0, a = e.suspendedLanes, o = e.pingedLanes;
    e = e.warmLanes;
    var s = r & 134217727;
    return s === 0 ? (s = r & ~a, s === 0 ? o === 0 ? n || (n = r & ~e, n !== 0 && (i = Ye(n))) : i = Ye(o) : i = Ye(s)) : (r = s & ~a, r === 0 ? (o &= s, o === 0 ? n || (n = s & ~e, n !== 0 && (i = Ye(n))) : i = Ye(o)) : i = Ye(r)), i === 0 ? 0 : t !== 0 && t !== i && (t & a) === 0 && (a = i & -i, n = t & -t, a >= n || a === 32 && n & 4194048) ? t : i;
  }
  function Ze(e, t) {
    return (e.pendingLanes & ~(e.suspendedLanes & ~e.pingedLanes) & t) === 0;
  }
  function Qe(e, t) {
    switch (e) {
      case 1:
      case 2:
      case 4:
      case 8:
      case 64: return t + 250;
      case 16:
      case 32:
      case 128:
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072:
      case 262144:
      case 524288:
      case 1048576:
      case 2097152: return t + 5e3;
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432: return -1;
      case 67108864:
      case 134217728:
      case 268435456:
      case 536870912:
      case 1073741824: return -1;
      default: return -1;
    }
  }
  function $e() {
    var e = Je;
    return Je <<= 1, !(Je & 62914560) && (Je = 4194304), e;
  }
  function et(e) {
    for (var t = [], n = 0; 31 > n; n++) t.push(e);
    return t;
  }
  function tt(e, t) {
    e.pendingLanes |= t, t !== 268435456 && (e.suspendedLanes = 0, e.pingedLanes = 0, e.warmLanes = 0);
  }
  function nt(e, t, n, r, i, a) {
    var o = e.pendingLanes;
    e.pendingLanes = n, e.suspendedLanes = 0, e.pingedLanes = 0, e.warmLanes = 0, e.expiredLanes &= n, e.entangledLanes &= n, e.errorRecoveryDisabledLanes &= n, e.shellSuspendCounter = 0;
    var s = e.entanglements, c = e.expirationTimes, l = e.hiddenUpdates;
    for (n = o & ~n; 0 < n;) {
      var u = 31 - He(n), d = 1 << u;
      s[u] = 0, c[u] = -1;
      var f = l[u];
      if (f !== null) for (l[u] = null, u = 0; u < f.length; u++) {
        var p = f[u];
        p !== null && (p.lane &= -536870913);
      }
      n &= ~d;
    }
    r !== 0 && rt(e, r, 0), a !== 0 && i === 0 && e.tag !== 0 && (e.suspendedLanes |= a & ~(o & ~t));
  }
  function rt(e, t, n) {
    e.pendingLanes |= t, e.suspendedLanes &= ~t;
    var r = 31 - He(t);
    e.entangledLanes |= t, e.entanglements[r] = e.entanglements[r] | 1073741824 | n & 261930;
  }
  function it(e, t) {
    var n = e.entangledLanes |= t;
    for (e = e.entanglements; n;) {
      var r = 31 - He(n), i = 1 << r;
      i & t | e[r] & t && (e[r] |= t), n &= ~i;
    }
  }
  function at(e, t) {
    var n = t & -t;
    return n = n & 42 ? 1 : ot(n), (n & (e.suspendedLanes | t)) === 0 ? n : 0;
  }
  function ot(e) {
    switch (e) {
      case 2:
        e = 1;
        break;
      case 8:
        e = 4;
        break;
      case 32:
        e = 16;
        break;
      case 256:
      case 512:
      case 1024:
      case 2048:
      case 4096:
      case 8192:
      case 16384:
      case 32768:
      case 65536:
      case 131072:
      case 262144:
      case 524288:
      case 1048576:
      case 2097152:
      case 4194304:
      case 8388608:
      case 16777216:
      case 33554432:
        e = 128;
        break;
      case 268435456:
        e = 134217728;
        break;
      default: e = 0;
    }
    return e;
  }
  function st(e) {
    return e &= -e, 2 < e ? 8 < e ? e & 134217727 ? 32 : 268435456 : 8 : 2;
  }
  function ct() {
    var e = A.p;
    return e === 0 ? (e = window.event, e === void 0 ? 32 : mp(e.type)) : e;
  }
  function lt(e, t) {
    var n = A.p;
    try {
      return A.p = e, t();
    } finally {
      A.p = n;
    }
  }
  var ut = Math.random().toString(36).slice(2), dt = "__reactFiber$" + ut, ft = "__reactProps$" + ut, pt = "__reactContainer$" + ut, mt = "__reactEvents$" + ut, ht = "__reactListeners$" + ut, gt = "__reactHandles$" + ut, _t = "__reactResources$" + ut, vt = "__reactMarker$" + ut;
  function yt(e) {
    delete e[dt], delete e[ft], delete e[mt], delete e[ht], delete e[gt];
  }
  function bt(e) {
    var t = e[dt];
    if (t) return t;
    for (var n = e.parentNode; n;) {
      if (t = n[pt] || n[dt]) {
        if (n = t.alternate, t.child !== null || n !== null && n.child !== null) for (e = df(e); e !== null;) {
          if (n = e[dt]) return n;
          e = df(e);
        }
        return t;
      }
      e = n, n = e.parentNode;
    }
    return null;
  }
  function xt(e) {
    if (e = e[dt] || e[pt]) {
      var t = e.tag;
      if (t === 5 || t === 6 || t === 13 || t === 31 || t === 26 || t === 27 || t === 3) return e;
    }
    return null;
  }
  function St(e) {
    var t = e.tag;
    if (t === 5 || t === 26 || t === 27 || t === 6) return e.stateNode;
    throw Error(i(33));
  }
  function Ct(e) {
    var t = e[_t];
    return t ||= e[_t] = {
      hoistableStyles: /* @__PURE__ */ new Map(),
      hoistableScripts: /* @__PURE__ */ new Map()
    }, t;
  }
  function wt(e) {
    e[vt] = !0;
  }
  var Tt = /* @__PURE__ */ new Set(), Et = {};
  function Dt(e, t) {
    Ot(e, t), Ot(e + "Capture", t);
  }
  function Ot(e, t) {
    for (Et[e] = t, e = 0; e < t.length; e++) Tt.add(t[e]);
  }
  var kt = RegExp("^[:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD][:A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$"), At = {}, jt = {};
  function Mt(e) {
    return N.call(jt, e) ? !0 : N.call(At, e) ? !1 : kt.test(e) ? jt[e] = !0 : (At[e] = !0, !1);
  }
  function Nt(e, t, n) {
    if (Mt(t)) if (n === null) e.removeAttribute(t);
    else {
      switch (typeof n) {
        case "undefined":
        case "function":
        case "symbol":
          e.removeAttribute(t);
          return;
        case "boolean":
          var r = t.toLowerCase().slice(0, 5);
          if (r !== "data-" && r !== "aria-") {
            e.removeAttribute(t);
            return;
          }
      }
      e.setAttribute(t, "" + n);
    }
  }
  function Pt(e, t, n) {
    if (n === null) e.removeAttribute(t);
    else {
      switch (typeof n) {
        case "undefined":
        case "function":
        case "symbol":
        case "boolean":
          e.removeAttribute(t);
          return;
      }
      e.setAttribute(t, "" + n);
    }
  }
  function Ft(e, t, n, r) {
    if (r === null) e.removeAttribute(n);
    else {
      switch (typeof r) {
        case "undefined":
        case "function":
        case "symbol":
        case "boolean":
          e.removeAttribute(n);
          return;
      }
      e.setAttributeNS(t, n, "" + r);
    }
  }
  function It(e) {
    switch (typeof e) {
      case "bigint":
      case "boolean":
      case "number":
      case "string":
      case "undefined": return e;
      case "object": return e;
      default: return "";
    }
  }
  function Lt(e) {
    var t = e.type;
    return (e = e.nodeName) && e.toLowerCase() === "input" && (t === "checkbox" || t === "radio");
  }
  function Rt(e, t, n) {
    var r = Object.getOwnPropertyDescriptor(e.constructor.prototype, t);
    if (!e.hasOwnProperty(t) && r !== void 0 && typeof r.get == "function" && typeof r.set == "function") {
      var i = r.get, a = r.set;
      return Object.defineProperty(e, t, {
        configurable: !0,
        get: function() {
          return i.call(this);
        },
        set: function(e) {
          n = "" + e, a.call(this, e);
        }
      }), Object.defineProperty(e, t, { enumerable: r.enumerable }), {
        getValue: function() {
          return n;
        },
        setValue: function(e) {
          n = "" + e;
        },
        stopTracking: function() {
          e._valueTracker = null, delete e[t];
        }
      };
    }
  }
  function zt(e) {
    if (!e._valueTracker) {
      var t = Lt(e) ? "checked" : "value";
      e._valueTracker = Rt(e, t, "" + e[t]);
    }
  }
  function P(e) {
    if (!e) return !1;
    var t = e._valueTracker;
    if (!t) return !0;
    var n = t.getValue(), r = "";
    return e && (r = Lt(e) ? e.checked ? "true" : "false" : e.value), e = r, e === n ? !1 : (t.setValue(e), !0);
  }
  function Bt(e) {
    if (e ||= typeof document < "u" ? document : void 0, e === void 0) return null;
    try {
      return e.activeElement || e.body;
    } catch {
      return e.body;
    }
  }
  var Vt = /[\n"\\]/g;
  function Ht(e) {
    return e.replace(Vt, function(e) {
      return "\\" + e.charCodeAt(0).toString(16) + " ";
    });
  }
  function Ut(e, t, n, r, i, a, o, s) {
    e.name = "", o != null && typeof o != "function" && typeof o != "symbol" && typeof o != "boolean" ? e.type = o : e.removeAttribute("type"), t == null ? o !== "submit" && o !== "reset" || e.removeAttribute("value") : o === "number" ? (t === 0 && e.value === "" || e.value != t) && (e.value = "" + It(t)) : e.value !== "" + It(t) && (e.value = "" + It(t)), t == null ? n == null ? r != null && e.removeAttribute("value") : Gt(e, o, It(n)) : Gt(e, o, It(t)), i == null && a != null && (e.defaultChecked = !!a), i != null && (e.checked = i && typeof i != "function" && typeof i != "symbol"), s != null && typeof s != "function" && typeof s != "symbol" && typeof s != "boolean" ? e.name = "" + It(s) : e.removeAttribute("name");
  }
  function Wt(e, t, n, r, i, a, o, s) {
    if (a != null && typeof a != "function" && typeof a != "symbol" && typeof a != "boolean" && (e.type = a), t != null || n != null) {
      if (!(a !== "submit" && a !== "reset" || t != null)) {
        zt(e);
        return;
      }
      n = n == null ? "" : "" + It(n), t = t == null ? n : "" + It(t), s || t === e.value || (e.value = t), e.defaultValue = t;
    }
    r ??= i, r = typeof r != "function" && typeof r != "symbol" && !!r, e.checked = s ? e.checked : !!r, e.defaultChecked = !!r, o != null && typeof o != "function" && typeof o != "symbol" && typeof o != "boolean" && (e.name = o), zt(e);
  }
  function Gt(e, t, n) {
    t === "number" && Bt(e.ownerDocument) === e || e.defaultValue === "" + n || (e.defaultValue = "" + n);
  }
  function Kt(e, t, n, r) {
    if (e = e.options, t) {
      t = {};
      for (var i = 0; i < n.length; i++) t["$" + n[i]] = !0;
      for (n = 0; n < e.length; n++) i = t.hasOwnProperty("$" + e[n].value), e[n].selected !== i && (e[n].selected = i), i && r && (e[n].defaultSelected = !0);
    } else {
      for (n = "" + It(n), t = null, i = 0; i < e.length; i++) {
        if (e[i].value === n) {
          e[i].selected = !0, r && (e[i].defaultSelected = !0);
          return;
        }
        t !== null || e[i].disabled || (t = e[i]);
      }
      t !== null && (t.selected = !0);
    }
  }
  function F(e, t, n) {
    if (t != null && (t = "" + It(t), t !== e.value && (e.value = t), n == null)) {
      e.defaultValue !== t && (e.defaultValue = t);
      return;
    }
    e.defaultValue = n == null ? "" : "" + It(n);
  }
  function qt(e, t, n, r) {
    if (t == null) {
      if (r != null) {
        if (n != null) throw Error(i(92));
        if (oe(r)) {
          if (1 < r.length) throw Error(i(93));
          r = r[0];
        }
        n = r;
      }
      n ??= "", t = n;
    }
    n = It(t), e.defaultValue = n, r = e.textContent, r === n && r !== "" && r !== null && (e.value = r), zt(e);
  }
  function Jt(e, t) {
    if (t) {
      var n = e.firstChild;
      if (n && n === e.lastChild && n.nodeType === 3) {
        n.nodeValue = t;
        return;
      }
    }
    e.textContent = t;
  }
  var Yt = new Set("animationIterationCount aspectRatio borderImageOutset borderImageSlice borderImageWidth boxFlex boxFlexGroup boxOrdinalGroup columnCount columns flex flexGrow flexPositive flexShrink flexNegative flexOrder gridArea gridRow gridRowEnd gridRowSpan gridRowStart gridColumn gridColumnEnd gridColumnSpan gridColumnStart fontWeight lineClamp lineHeight opacity order orphans scale tabSize widows zIndex zoom fillOpacity floodOpacity stopOpacity strokeDasharray strokeDashoffset strokeMiterlimit strokeOpacity strokeWidth MozAnimationIterationCount MozBoxFlex MozBoxFlexGroup MozLineClamp msAnimationIterationCount msFlex msZoom msFlexGrow msFlexNegative msFlexOrder msFlexPositive msFlexShrink msGridColumn msGridColumnSpan msGridRow msGridRowSpan WebkitAnimationIterationCount WebkitBoxFlex WebKitBoxFlexGroup WebkitBoxOrdinalGroup WebkitColumnCount WebkitColumns WebkitFlex WebkitFlexGrow WebkitFlexPositive WebkitFlexShrink WebkitLineClamp".split(" "));
  function Xt(e, t, n) {
    var r = t.indexOf("--") === 0;
    n == null || typeof n == "boolean" || n === "" ? r ? e.setProperty(t, "") : t === "float" ? e.cssFloat = "" : e[t] = "" : r ? e.setProperty(t, n) : typeof n != "number" || n === 0 || Yt.has(t) ? t === "float" ? e.cssFloat = n : e[t] = ("" + n).trim() : e[t] = n + "px";
  }
  function Zt(e, t, n) {
    if (t != null && typeof t != "object") throw Error(i(62));
    if (e = e.style, n != null) {
      for (var r in n) !n.hasOwnProperty(r) || t != null && t.hasOwnProperty(r) || (r.indexOf("--") === 0 ? e.setProperty(r, "") : r === "float" ? e.cssFloat = "" : e[r] = "");
      for (var a in t) r = t[a], t.hasOwnProperty(a) && n[a] !== r && Xt(e, a, r);
    } else for (var o in t) t.hasOwnProperty(o) && Xt(e, o, t[o]);
  }
  function Qt(e) {
    if (e.indexOf("-") === -1) return !1;
    switch (e) {
      case "annotation-xml":
      case "color-profile":
      case "font-face":
      case "font-face-src":
      case "font-face-uri":
      case "font-face-format":
      case "font-face-name":
      case "missing-glyph": return !1;
      default: return !0;
    }
  }
  var $t = /* @__PURE__ */ new Map([
    ["acceptCharset", "accept-charset"],
    ["htmlFor", "for"],
    ["httpEquiv", "http-equiv"],
    ["crossOrigin", "crossorigin"],
    ["accentHeight", "accent-height"],
    ["alignmentBaseline", "alignment-baseline"],
    ["arabicForm", "arabic-form"],
    ["baselineShift", "baseline-shift"],
    ["capHeight", "cap-height"],
    ["clipPath", "clip-path"],
    ["clipRule", "clip-rule"],
    ["colorInterpolation", "color-interpolation"],
    ["colorInterpolationFilters", "color-interpolation-filters"],
    ["colorProfile", "color-profile"],
    ["colorRendering", "color-rendering"],
    ["dominantBaseline", "dominant-baseline"],
    ["enableBackground", "enable-background"],
    ["fillOpacity", "fill-opacity"],
    ["fillRule", "fill-rule"],
    ["floodColor", "flood-color"],
    ["floodOpacity", "flood-opacity"],
    ["fontFamily", "font-family"],
    ["fontSize", "font-size"],
    ["fontSizeAdjust", "font-size-adjust"],
    ["fontStretch", "font-stretch"],
    ["fontStyle", "font-style"],
    ["fontVariant", "font-variant"],
    ["fontWeight", "font-weight"],
    ["glyphName", "glyph-name"],
    ["glyphOrientationHorizontal", "glyph-orientation-horizontal"],
    ["glyphOrientationVertical", "glyph-orientation-vertical"],
    ["horizAdvX", "horiz-adv-x"],
    ["horizOriginX", "horiz-origin-x"],
    ["imageRendering", "image-rendering"],
    ["letterSpacing", "letter-spacing"],
    ["lightingColor", "lighting-color"],
    ["markerEnd", "marker-end"],
    ["markerMid", "marker-mid"],
    ["markerStart", "marker-start"],
    ["overlinePosition", "overline-position"],
    ["overlineThickness", "overline-thickness"],
    ["paintOrder", "paint-order"],
    ["panose-1", "panose-1"],
    ["pointerEvents", "pointer-events"],
    ["renderingIntent", "rendering-intent"],
    ["shapeRendering", "shape-rendering"],
    ["stopColor", "stop-color"],
    ["stopOpacity", "stop-opacity"],
    ["strikethroughPosition", "strikethrough-position"],
    ["strikethroughThickness", "strikethrough-thickness"],
    ["strokeDasharray", "stroke-dasharray"],
    ["strokeDashoffset", "stroke-dashoffset"],
    ["strokeLinecap", "stroke-linecap"],
    ["strokeLinejoin", "stroke-linejoin"],
    ["strokeMiterlimit", "stroke-miterlimit"],
    ["strokeOpacity", "stroke-opacity"],
    ["strokeWidth", "stroke-width"],
    ["textAnchor", "text-anchor"],
    ["textDecoration", "text-decoration"],
    ["textRendering", "text-rendering"],
    ["transformOrigin", "transform-origin"],
    ["underlinePosition", "underline-position"],
    ["underlineThickness", "underline-thickness"],
    ["unicodeBidi", "unicode-bidi"],
    ["unicodeRange", "unicode-range"],
    ["unitsPerEm", "units-per-em"],
    ["vAlphabetic", "v-alphabetic"],
    ["vHanging", "v-hanging"],
    ["vIdeographic", "v-ideographic"],
    ["vMathematical", "v-mathematical"],
    ["vectorEffect", "vector-effect"],
    ["vertAdvY", "vert-adv-y"],
    ["vertOriginX", "vert-origin-x"],
    ["vertOriginY", "vert-origin-y"],
    ["wordSpacing", "word-spacing"],
    ["writingMode", "writing-mode"],
    ["xmlnsXlink", "xmlns:xlink"],
    ["xHeight", "x-height"]
  ]), en = /^[\u0000-\u001F ]*j[\r\n\t]*a[\r\n\t]*v[\r\n\t]*a[\r\n\t]*s[\r\n\t]*c[\r\n\t]*r[\r\n\t]*i[\r\n\t]*p[\r\n\t]*t[\r\n\t]*:/i;
  function tn(e) {
    return en.test("" + e) ? "javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')" : e;
  }
  function nn() {}
  var rn = null;
  function an(e) {
    return e = e.target || e.srcElement || window, e.correspondingUseElement && (e = e.correspondingUseElement), e.nodeType === 3 ? e.parentNode : e;
  }
  var on = null, sn = null;
  function cn(e) {
    var t = xt(e);
    if (t && (e = t.stateNode)) {
      var n = e[ft] || null;
      a: switch (e = t.stateNode, t.type) {
        case "input":
          if (Ut(e, n.value, n.defaultValue, n.defaultValue, n.checked, n.defaultChecked, n.type, n.name), t = n.name, n.type === "radio" && t != null) {
            for (n = e; n.parentNode;) n = n.parentNode;
            for (n = n.querySelectorAll("input[name=\"" + Ht("" + t) + "\"][type=\"radio\"]"), t = 0; t < n.length; t++) {
              var r = n[t];
              if (r !== e && r.form === e.form) {
                var a = r[ft] || null;
                if (!a) throw Error(i(90));
                Ut(r, a.value, a.defaultValue, a.defaultValue, a.checked, a.defaultChecked, a.type, a.name);
              }
            }
            for (t = 0; t < n.length; t++) r = n[t], r.form === e.form && P(r);
          }
          break a;
        case "textarea":
          F(e, n.value, n.defaultValue);
          break a;
        case "select": t = n.value, t != null && Kt(e, !!n.multiple, t, !1);
      }
    }
  }
  var ln = !1;
  function un(e, t, n) {
    if (ln) return e(t, n);
    ln = !0;
    try {
      return e(t);
    } finally {
      if (ln = !1, (on !== null || sn !== null) && (_u(), on && (t = on, e = sn, sn = on = null, cn(t), e))) for (t = 0; t < e.length; t++) cn(e[t]);
    }
  }
  function dn(e, t) {
    var n = e.stateNode;
    if (n === null) return null;
    var r = n[ft] || null;
    if (r === null) return null;
    n = r[t];
    a: switch (t) {
      case "onClick":
      case "onClickCapture":
      case "onDoubleClick":
      case "onDoubleClickCapture":
      case "onMouseDown":
      case "onMouseDownCapture":
      case "onMouseMove":
      case "onMouseMoveCapture":
      case "onMouseUp":
      case "onMouseUpCapture":
      case "onMouseEnter":
        (r = !r.disabled) || (e = e.type, r = !(e === "button" || e === "input" || e === "select" || e === "textarea")), e = !r;
        break a;
      default: e = !1;
    }
    if (e) return null;
    if (n && typeof n != "function") throw Error(i(231, t, typeof n));
    return n;
  }
  var fn = !(typeof window > "u" || window.document === void 0 || window.document.createElement === void 0), pn = !1;
  if (fn) try {
    var I = {};
    Object.defineProperty(I, "passive", { get: function() {
      pn = !0;
    } }), window.addEventListener("test", I, I), window.removeEventListener("test", I, I);
  } catch {
    pn = !1;
  }
  var mn = null, hn = null, gn = null;
  function _n() {
    if (gn) return gn;
    var e, t = hn, n = t.length, r, i = "value" in mn ? mn.value : mn.textContent, a = i.length;
    for (e = 0; e < n && t[e] === i[e]; e++);
    var o = n - e;
    for (r = 1; r <= o && t[n - r] === i[a - r]; r++);
    return gn = i.slice(e, 1 < r ? 1 - r : void 0);
  }
  function vn(e) {
    var t = e.keyCode;
    return "charCode" in e ? (e = e.charCode, e === 0 && t === 13 && (e = 13)) : e = t, e === 10 && (e = 13), 32 <= e || e === 13 ? e : 0;
  }
  function yn() {
    return !0;
  }
  function bn() {
    return !1;
  }
  function xn(e) {
    function t(t, n, r, i, a) {
      for (var o in this._reactName = t, this._targetInst = r, this.type = n, this.nativeEvent = i, this.target = a, this.currentTarget = null, e) e.hasOwnProperty(o) && (t = e[o], this[o] = t ? t(i) : i[o]);
      return this.isDefaultPrevented = (i.defaultPrevented == null ? !1 === i.returnValue : i.defaultPrevented) ? yn : bn, this.isPropagationStopped = bn, this;
    }
    return h(t.prototype, {
      preventDefault: function() {
        this.defaultPrevented = !0;
        var e = this.nativeEvent;
        e && (e.preventDefault ? e.preventDefault() : typeof e.returnValue != "unknown" && (e.returnValue = !1), this.isDefaultPrevented = yn);
      },
      stopPropagation: function() {
        var e = this.nativeEvent;
        e && (e.stopPropagation ? e.stopPropagation() : typeof e.cancelBubble != "unknown" && (e.cancelBubble = !0), this.isPropagationStopped = yn);
      },
      persist: function() {},
      isPersistent: yn
    }), t;
  }
  var Sn = {
    eventPhase: 0,
    bubbles: 0,
    cancelable: 0,
    timeStamp: function(e) {
      return e.timeStamp || Date.now();
    },
    defaultPrevented: 0,
    isTrusted: 0
  }, Cn = xn(Sn), wn = h({}, Sn, {
    view: 0,
    detail: 0
  }), Tn = xn(wn), En, Dn, On, kn = h({}, wn, {
    screenX: 0,
    screenY: 0,
    clientX: 0,
    clientY: 0,
    pageX: 0,
    pageY: 0,
    ctrlKey: 0,
    shiftKey: 0,
    altKey: 0,
    metaKey: 0,
    getModifierState: zn,
    button: 0,
    buttons: 0,
    relatedTarget: function(e) {
      return e.relatedTarget === void 0 ? e.fromElement === e.srcElement ? e.toElement : e.fromElement : e.relatedTarget;
    },
    movementX: function(e) {
      return "movementX" in e ? e.movementX : (e !== On && (On && e.type === "mousemove" ? (En = e.screenX - On.screenX, Dn = e.screenY - On.screenY) : Dn = En = 0, On = e), En);
    },
    movementY: function(e) {
      return "movementY" in e ? e.movementY : Dn;
    }
  }), An = xn(kn), jn = xn(h({}, kn, { dataTransfer: 0 })), Mn = xn(h({}, wn, { relatedTarget: 0 })), Nn = xn(h({}, Sn, {
    animationName: 0,
    elapsedTime: 0,
    pseudoElement: 0
  })), Pn = xn(h({}, Sn, { clipboardData: function(e) {
    return "clipboardData" in e ? e.clipboardData : window.clipboardData;
  } })), Fn = xn(h({}, Sn, { data: 0 })), In = {
    Esc: "Escape",
    Spacebar: " ",
    Left: "ArrowLeft",
    Up: "ArrowUp",
    Right: "ArrowRight",
    Down: "ArrowDown",
    Del: "Delete",
    Win: "OS",
    Menu: "ContextMenu",
    Apps: "ContextMenu",
    Scroll: "ScrollLock",
    MozPrintableKey: "Unidentified"
  }, L = {
    8: "Backspace",
    9: "Tab",
    12: "Clear",
    13: "Enter",
    16: "Shift",
    17: "Control",
    18: "Alt",
    19: "Pause",
    20: "CapsLock",
    27: "Escape",
    32: " ",
    33: "PageUp",
    34: "PageDown",
    35: "End",
    36: "Home",
    37: "ArrowLeft",
    38: "ArrowUp",
    39: "ArrowRight",
    40: "ArrowDown",
    45: "Insert",
    46: "Delete",
    112: "F1",
    113: "F2",
    114: "F3",
    115: "F4",
    116: "F5",
    117: "F6",
    118: "F7",
    119: "F8",
    120: "F9",
    121: "F10",
    122: "F11",
    123: "F12",
    144: "NumLock",
    145: "ScrollLock",
    224: "Meta"
  }, Ln = {
    Alt: "altKey",
    Control: "ctrlKey",
    Meta: "metaKey",
    Shift: "shiftKey"
  };
  function Rn(e) {
    var t = this.nativeEvent;
    return t.getModifierState ? t.getModifierState(e) : (e = Ln[e]) ? !!t[e] : !1;
  }
  function zn() {
    return Rn;
  }
  var Bn = xn(h({}, wn, {
    key: function(e) {
      if (e.key) {
        var t = In[e.key] || e.key;
        if (t !== "Unidentified") return t;
      }
      return e.type === "keypress" ? (e = vn(e), e === 13 ? "Enter" : String.fromCharCode(e)) : e.type === "keydown" || e.type === "keyup" ? L[e.keyCode] || "Unidentified" : "";
    },
    code: 0,
    location: 0,
    ctrlKey: 0,
    shiftKey: 0,
    altKey: 0,
    metaKey: 0,
    repeat: 0,
    locale: 0,
    getModifierState: zn,
    charCode: function(e) {
      return e.type === "keypress" ? vn(e) : 0;
    },
    keyCode: function(e) {
      return e.type === "keydown" || e.type === "keyup" ? e.keyCode : 0;
    },
    which: function(e) {
      return e.type === "keypress" ? vn(e) : e.type === "keydown" || e.type === "keyup" ? e.keyCode : 0;
    }
  })), Vn = xn(h({}, kn, {
    pointerId: 0,
    width: 0,
    height: 0,
    pressure: 0,
    tangentialPressure: 0,
    tiltX: 0,
    tiltY: 0,
    twist: 0,
    pointerType: 0,
    isPrimary: 0
  })), Hn = xn(h({}, wn, {
    touches: 0,
    targetTouches: 0,
    changedTouches: 0,
    altKey: 0,
    metaKey: 0,
    ctrlKey: 0,
    shiftKey: 0,
    getModifierState: zn
  })), Un = xn(h({}, Sn, {
    propertyName: 0,
    elapsedTime: 0,
    pseudoElement: 0
  })), Wn = xn(h({}, kn, {
    deltaX: function(e) {
      return "deltaX" in e ? e.deltaX : "wheelDeltaX" in e ? -e.wheelDeltaX : 0;
    },
    deltaY: function(e) {
      return "deltaY" in e ? e.deltaY : "wheelDeltaY" in e ? -e.wheelDeltaY : "wheelDelta" in e ? -e.wheelDelta : 0;
    },
    deltaZ: 0,
    deltaMode: 0
  })), Gn = xn(h({}, Sn, {
    newState: 0,
    oldState: 0
  })), Kn = [
    9,
    13,
    27,
    32
  ], qn = fn && "CompositionEvent" in window, Jn = null;
  fn && "documentMode" in document && (Jn = document.documentMode);
  var Yn = fn && "TextEvent" in window && !Jn, Xn = fn && (!qn || Jn && 8 < Jn && 11 >= Jn), Zn = " ", Qn = !1;
  function $n(e, t) {
    switch (e) {
      case "keyup": return Kn.indexOf(t.keyCode) !== -1;
      case "keydown": return t.keyCode !== 229;
      case "keypress":
      case "mousedown":
      case "focusout": return !0;
      default: return !1;
    }
  }
  function er(e) {
    return e = e.detail, typeof e == "object" && "data" in e ? e.data : null;
  }
  var tr = !1;
  function nr(e, t) {
    switch (e) {
      case "compositionend": return er(t);
      case "keypress": return t.which === 32 ? (Qn = !0, Zn) : null;
      case "textInput": return e = t.data, e === Zn && Qn ? null : e;
      default: return null;
    }
  }
  function rr(e, t) {
    if (tr) return e === "compositionend" || !qn && $n(e, t) ? (e = _n(), gn = hn = mn = null, tr = !1, e) : null;
    switch (e) {
      case "paste": return null;
      case "keypress":
        if (!(t.ctrlKey || t.altKey || t.metaKey) || t.ctrlKey && t.altKey) {
          if (t.char && 1 < t.char.length) return t.char;
          if (t.which) return String.fromCharCode(t.which);
        }
        return null;
      case "compositionend": return Xn && t.locale !== "ko" ? null : t.data;
      default: return null;
    }
  }
  var ir = {
    color: !0,
    date: !0,
    datetime: !0,
    "datetime-local": !0,
    email: !0,
    month: !0,
    number: !0,
    password: !0,
    range: !0,
    search: !0,
    tel: !0,
    text: !0,
    time: !0,
    url: !0,
    week: !0
  };
  function ar(e) {
    var t = e && e.nodeName && e.nodeName.toLowerCase();
    return t === "input" ? !!ir[e.type] : t === "textarea";
  }
  function R(e, t, n, r) {
    on ? sn ? sn.push(r) : sn = [r] : on = r, t = Td(t, "onChange"), 0 < t.length && (n = new Cn("onChange", "change", null, n, r), e.push({
      event: n,
      listeners: t
    }));
  }
  var or = null, z = null;
  function sr(e) {
    _d(e, 0);
  }
  function B(e) {
    if (P(St(e))) return e;
  }
  function V(e, t) {
    if (e === "change") return t;
  }
  var cr = !1;
  if (fn) {
    var lr;
    if (fn) {
      var ur = "oninput" in document;
      if (!ur) {
        var dr = document.createElement("div");
        dr.setAttribute("oninput", "return;"), ur = typeof dr.oninput == "function";
      }
      lr = ur;
    } else lr = !1;
    cr = lr && (!document.documentMode || 9 < document.documentMode);
  }
  function fr() {
    or && (or.detachEvent("onpropertychange", pr), z = or = null);
  }
  function pr(e) {
    if (e.propertyName === "value" && B(z)) {
      var t = [];
      R(t, z, e, an(e)), un(sr, t);
    }
  }
  function H(e, t, n) {
    e === "focusin" ? (fr(), or = t, z = n, or.attachEvent("onpropertychange", pr)) : e === "focusout" && fr();
  }
  function U(e) {
    if (e === "selectionchange" || e === "keyup" || e === "keydown") return B(z);
  }
  function W(e, t) {
    if (e === "click") return B(t);
  }
  function G(e, t) {
    if (e === "input" || e === "change") return B(t);
  }
  function K(e, t) {
    return e === t && (e !== 0 || 1 / e == 1 / t) || e !== e && t !== t;
  }
  var mr = typeof Object.is == "function" ? Object.is : K;
  function hr(e, t) {
    if (mr(e, t)) return !0;
    if (typeof e != "object" || !e || typeof t != "object" || !t) return !1;
    var n = Object.keys(e), r = Object.keys(t);
    if (n.length !== r.length) return !1;
    for (r = 0; r < n.length; r++) {
      var i = n[r];
      if (!N.call(t, i) || !mr(e[i], t[i])) return !1;
    }
    return !0;
  }
  function gr(e) {
    for (; e && e.firstChild;) e = e.firstChild;
    return e;
  }
  function _r(e, t) {
    var n = gr(e);
    e = 0;
    for (var r; n;) {
      if (n.nodeType === 3) {
        if (r = e + n.textContent.length, e <= t && r >= t) return {
          node: n,
          offset: t - e
        };
        e = r;
      }
      a: {
        for (; n;) {
          if (n.nextSibling) {
            n = n.nextSibling;
            break a;
          }
          n = n.parentNode;
        }
        n = void 0;
      }
      n = gr(n);
    }
  }
  function vr(e, t) {
    return e && t ? e === t ? !0 : e && e.nodeType === 3 ? !1 : t && t.nodeType === 3 ? vr(e, t.parentNode) : "contains" in e ? e.contains(t) : e.compareDocumentPosition ? !!(e.compareDocumentPosition(t) & 16) : !1 : !1;
  }
  function yr(e) {
    e = e != null && e.ownerDocument != null && e.ownerDocument.defaultView != null ? e.ownerDocument.defaultView : window;
    for (var t = Bt(e.document); t instanceof e.HTMLIFrameElement;) {
      try {
        var n = typeof t.contentWindow.location.href == "string";
      } catch {
        n = !1;
      }
      if (n) e = t.contentWindow;
      else break;
      t = Bt(e.document);
    }
    return t;
  }
  function br(e) {
    var t = e && e.nodeName && e.nodeName.toLowerCase();
    return t && (t === "input" && (e.type === "text" || e.type === "search" || e.type === "tel" || e.type === "url" || e.type === "password") || t === "textarea" || e.contentEditable === "true");
  }
  var xr = fn && "documentMode" in document && 11 >= document.documentMode, Sr = null, Cr = null, wr = null, Tr = !1;
  function Er(e, t, n) {
    var r = n.window === n ? n.document : n.nodeType === 9 ? n : n.ownerDocument;
    Tr || Sr == null || Sr !== Bt(r) || (r = Sr, "selectionStart" in r && br(r) ? r = {
      start: r.selectionStart,
      end: r.selectionEnd
    } : (r = (r.ownerDocument && r.ownerDocument.defaultView || window).getSelection(), r = {
      anchorNode: r.anchorNode,
      anchorOffset: r.anchorOffset,
      focusNode: r.focusNode,
      focusOffset: r.focusOffset
    }), wr && hr(wr, r) || (wr = r, r = Td(Cr, "onSelect"), 0 < r.length && (t = new Cn("onSelect", "select", null, t, n), e.push({
      event: t,
      listeners: r
    }), t.target = Sr)));
  }
  function Dr(e, t) {
    var n = {};
    return n[e.toLowerCase()] = t.toLowerCase(), n["Webkit" + e] = "webkit" + t, n["Moz" + e] = "moz" + t, n;
  }
  var q = {
    animationend: Dr("Animation", "AnimationEnd"),
    animationiteration: Dr("Animation", "AnimationIteration"),
    animationstart: Dr("Animation", "AnimationStart"),
    transitionrun: Dr("Transition", "TransitionRun"),
    transitionstart: Dr("Transition", "TransitionStart"),
    transitioncancel: Dr("Transition", "TransitionCancel"),
    transitionend: Dr("Transition", "TransitionEnd")
  }, Or = {}, kr = {};
  fn && (kr = document.createElement("div").style, "AnimationEvent" in window || (delete q.animationend.animation, delete q.animationiteration.animation, delete q.animationstart.animation), "TransitionEvent" in window || delete q.transitionend.transition);
  function J(e) {
    if (Or[e]) return Or[e];
    if (!q[e]) return e;
    var t = q[e], n;
    for (n in t) if (t.hasOwnProperty(n) && n in kr) return Or[e] = t[n];
    return e;
  }
  var Ar = J("animationend"), jr = J("animationiteration"), Mr = J("animationstart"), Nr = J("transitionrun"), Pr = J("transitionstart"), Fr = J("transitioncancel"), Ir = J("transitionend"), Lr = /* @__PURE__ */ new Map(), Rr = "abort auxClick beforeToggle cancel canPlay canPlayThrough click close contextMenu copy cut drag dragEnd dragEnter dragExit dragLeave dragOver dragStart drop durationChange emptied encrypted ended error gotPointerCapture input invalid keyDown keyPress keyUp load loadedData loadedMetadata loadStart lostPointerCapture mouseDown mouseMove mouseOut mouseOver mouseUp paste pause play playing pointerCancel pointerDown pointerMove pointerOut pointerOver pointerUp progress rateChange reset resize seeked seeking stalled submit suspend timeUpdate touchCancel touchEnd touchStart volumeChange scroll toggle touchMove waiting wheel".split(" ");
  Rr.push("scrollEnd");
  function zr(e, t) {
    Lr.set(e, t), Dt(t, [e]);
  }
  var Br = typeof reportError == "function" ? reportError : function(e) {
    if (typeof window == "object" && typeof window.ErrorEvent == "function") {
      var t = new window.ErrorEvent("error", {
        bubbles: !0,
        cancelable: !0,
        message: typeof e == "object" && e && typeof e.message == "string" ? String(e.message) : String(e),
        error: e
      });
      if (!window.dispatchEvent(t)) return;
    } else if (typeof process == "object" && typeof process.emit == "function") {
      process.emit("uncaughtException", e);
      return;
    }
    console.error(e);
  }, Vr = [], Hr = 0, Ur = 0;
  function Wr() {
    for (var e = Hr, t = Ur = Hr = 0; t < e;) {
      var n = Vr[t];
      Vr[t++] = null;
      var r = Vr[t];
      Vr[t++] = null;
      var i = Vr[t];
      Vr[t++] = null;
      var a = Vr[t];
      if (Vr[t++] = null, r !== null && i !== null) {
        var o = r.pending;
        o === null ? i.next = i : (i.next = o.next, o.next = i), r.pending = i;
      }
      a !== 0 && Jr(n, i, a);
    }
  }
  function Gr(e, t, n, r) {
    Vr[Hr++] = e, Vr[Hr++] = t, Vr[Hr++] = n, Vr[Hr++] = r, Ur |= r, e.lanes |= r, e = e.alternate, e !== null && (e.lanes |= r);
  }
  function Kr(e, t, n, r) {
    return Gr(e, t, n, r), Yr(e);
  }
  function qr(e, t) {
    return Gr(e, null, null, t), Yr(e);
  }
  function Jr(e, t, n) {
    e.lanes |= n;
    var r = e.alternate;
    r !== null && (r.lanes |= n);
    for (var i = !1, a = e.return; a !== null;) a.childLanes |= n, r = a.alternate, r !== null && (r.childLanes |= n), a.tag === 22 && (e = a.stateNode, e === null || e._visibility & 1 || (i = !0)), e = a, a = a.return;
    return e.tag === 3 ? (a = e.stateNode, i && t !== null && (i = 31 - He(n), e = a.hiddenUpdates, r = e[i], r === null ? e[i] = [t] : r.push(t), t.lane = n | 536870912), a) : null;
  }
  function Yr(e) {
    if (50 < cu) throw cu = 0, lu = null, Error(i(185));
    for (var t = e.return; t !== null;) e = t, t = e.return;
    return e.tag === 3 ? e.stateNode : null;
  }
  var Xr = {};
  function Zr(e, t, n, r) {
    this.tag = e, this.key = n, this.sibling = this.child = this.return = this.stateNode = this.type = this.elementType = null, this.index = 0, this.refCleanup = this.ref = null, this.pendingProps = t, this.dependencies = this.memoizedState = this.updateQueue = this.memoizedProps = null, this.mode = r, this.subtreeFlags = this.flags = 0, this.deletions = null, this.childLanes = this.lanes = 0, this.alternate = null;
  }
  function Qr(e, t, n, r) {
    return new Zr(e, t, n, r);
  }
  function $r(e) {
    return e = e.prototype, !(!e || !e.isReactComponent);
  }
  function ei(e, t) {
    var n = e.alternate;
    return n === null ? (n = Qr(e.tag, t, e.key, e.mode), n.elementType = e.elementType, n.type = e.type, n.stateNode = e.stateNode, n.alternate = e, e.alternate = n) : (n.pendingProps = t, n.type = e.type, n.flags = 0, n.subtreeFlags = 0, n.deletions = null), n.flags = e.flags & 65011712, n.childLanes = e.childLanes, n.lanes = e.lanes, n.child = e.child, n.memoizedProps = e.memoizedProps, n.memoizedState = e.memoizedState, n.updateQueue = e.updateQueue, t = e.dependencies, n.dependencies = t === null ? null : {
      lanes: t.lanes,
      firstContext: t.firstContext
    }, n.sibling = e.sibling, n.index = e.index, n.ref = e.ref, n.refCleanup = e.refCleanup, n;
  }
  function ti(e, t) {
    e.flags &= 65011714;
    var n = e.alternate;
    return n === null ? (e.childLanes = 0, e.lanes = t, e.child = null, e.subtreeFlags = 0, e.memoizedProps = null, e.memoizedState = null, e.updateQueue = null, e.dependencies = null, e.stateNode = null) : (e.childLanes = n.childLanes, e.lanes = n.lanes, e.child = n.child, e.subtreeFlags = 0, e.deletions = null, e.memoizedProps = n.memoizedProps, e.memoizedState = n.memoizedState, e.updateQueue = n.updateQueue, e.type = n.type, t = n.dependencies, e.dependencies = t === null ? null : {
      lanes: t.lanes,
      firstContext: t.firstContext
    }), e;
  }
  function ni(e, t, n, r, a, o) {
    var s = 0;
    if (r = e, typeof e == "function") $r(e) && (s = 1);
    else if (typeof e == "string") s = Uf(e, n, de.current) ? 26 : e === "html" || e === "head" || e === "body" ? 27 : 5;
    else a: switch (e) {
      case ee: return e = Qr(31, n, t, a), e.elementType = ee, e.lanes = o, e;
      case y: return ri(n.children, a, o, t);
      case b:
        s = 8, a |= 24;
        break;
      case x: return e = Qr(12, n, t, a | 2), e.elementType = x, e.lanes = o, e;
      case T: return e = Qr(13, n, t, a), e.elementType = T, e.lanes = o, e;
      case E: return e = Qr(19, n, t, a), e.elementType = E, e.lanes = o, e;
      default:
        if (typeof e == "object" && e) switch (e.$$typeof) {
          case C:
            s = 10;
            break a;
          case S:
            s = 9;
            break a;
          case w:
            s = 11;
            break a;
          case D:
            s = 14;
            break a;
          case O:
            s = 16, r = null;
            break a;
        }
        s = 29, n = Error(i(130, e === null ? "null" : typeof e, "")), r = null;
    }
    return t = Qr(s, n, t, a), t.elementType = e, t.type = r, t.lanes = o, t;
  }
  function ri(e, t, n, r) {
    return e = Qr(7, e, r, t), e.lanes = n, e;
  }
  function ii(e, t, n) {
    return e = Qr(6, e, null, t), e.lanes = n, e;
  }
  function ai(e) {
    var t = Qr(18, null, null, 0);
    return t.stateNode = e, t;
  }
  function oi(e, t, n) {
    return t = Qr(4, e.children === null ? [] : e.children, e.key, t), t.lanes = n, t.stateNode = {
      containerInfo: e.containerInfo,
      pendingChildren: null,
      implementation: e.implementation
    }, t;
  }
  var si = /* @__PURE__ */ new WeakMap();
  function ci(e, t) {
    if (typeof e == "object" && e) {
      var n = si.get(e);
      return n === void 0 ? (t = {
        value: e,
        source: t,
        stack: Te(t)
      }, si.set(e, t), t) : n;
    }
    return {
      value: e,
      source: t,
      stack: Te(t)
    };
  }
  var li = [], ui = 0, di = null, fi = 0, pi = [], mi = 0, hi = null, gi = 1, _i = "";
  function vi(e, t) {
    li[ui++] = fi, li[ui++] = di, di = e, fi = t;
  }
  function yi(e, t, n) {
    pi[mi++] = gi, pi[mi++] = _i, pi[mi++] = hi, hi = e;
    var r = gi;
    e = _i;
    var i = 32 - He(r) - 1;
    r &= ~(1 << i), n += 1;
    var a = 32 - He(t) + i;
    if (30 < a) {
      var o = i - i % 5;
      a = (r & (1 << o) - 1).toString(32), r >>= o, i -= o, gi = 1 << 32 - He(t) + i | n << i | r, _i = a + e;
    } else gi = 1 << a | n << i | r, _i = e;
  }
  function bi(e) {
    e.return !== null && (vi(e, 1), yi(e, 1, 0));
  }
  function xi(e) {
    for (; e === di;) di = li[--ui], li[ui] = null, fi = li[--ui], li[ui] = null;
    for (; e === hi;) hi = pi[--mi], pi[mi] = null, _i = pi[--mi], pi[mi] = null, gi = pi[--mi], pi[mi] = null;
  }
  function Si(e, t) {
    pi[mi++] = gi, pi[mi++] = _i, pi[mi++] = hi, gi = t.id, _i = t.overflow, hi = e;
  }
  var Ci = null, wi = null, Ti = !1, Ei = null, Di = !1, Oi = Error(i(519));
  function ki(e) {
    throw Fi(ci(Error(i(418, 1 < arguments.length && arguments[1] !== void 0 && arguments[1] ? "text" : "HTML", "")), e)), Oi;
  }
  function Ai(e) {
    var t = e.stateNode, n = e.type, r = e.memoizedProps;
    switch (t[dt] = e, t[ft] = r, n) {
      case "dialog":
        vd("cancel", t), vd("close", t);
        break;
      case "iframe":
      case "object":
      case "embed":
        vd("load", t);
        break;
      case "video":
      case "audio":
        for (n = 0; n < hd.length; n++) vd(hd[n], t);
        break;
      case "source":
        vd("error", t);
        break;
      case "img":
      case "image":
      case "link":
        vd("error", t), vd("load", t);
        break;
      case "details":
        vd("toggle", t);
        break;
      case "input":
        vd("invalid", t), Wt(t, r.value, r.defaultValue, r.checked, r.defaultChecked, r.type, r.name, !0);
        break;
      case "select":
        vd("invalid", t);
        break;
      case "textarea": vd("invalid", t), qt(t, r.value, r.defaultValue, r.children);
    }
    n = r.children, typeof n != "string" && typeof n != "number" && typeof n != "bigint" || t.textContent === "" + n || !0 === r.suppressHydrationWarning || jd(t.textContent, n) ? (r.popover != null && (vd("beforetoggle", t), vd("toggle", t)), r.onScroll != null && vd("scroll", t), r.onScrollEnd != null && vd("scrollend", t), r.onClick != null && (t.onclick = nn), t = !0) : t = !1, t || ki(e, !0);
  }
  function ji(e) {
    for (Ci = e.return; Ci;) switch (Ci.tag) {
      case 5:
      case 31:
      case 13:
        Di = !1;
        return;
      case 27:
      case 3:
        Di = !0;
        return;
      default: Ci = Ci.return;
    }
  }
  function Mi(e) {
    if (e !== Ci) return !1;
    if (!Ti) return ji(e), Ti = !0, !1;
    var t = e.tag, n;
    if ((n = t !== 3 && t !== 27) && ((n = t === 5) && (n = e.type, n = !(n !== "form" && n !== "button") || Ud(e.type, e.memoizedProps)), n = !n), n && wi && ki(e), ji(e), t === 13) {
      if (e = e.memoizedState, e = e === null ? null : e.dehydrated, !e) throw Error(i(317));
      wi = uf(e);
    } else if (t === 31) {
      if (e = e.memoizedState, e = e === null ? null : e.dehydrated, !e) throw Error(i(317));
      wi = uf(e);
    } else t === 27 ? (t = wi, Zd(e.type) ? (e = lf, lf = null, wi = e) : wi = t) : wi = Ci ? cf(e.stateNode.nextSibling) : null;
    return !0;
  }
  function Ni() {
    wi = Ci = null, Ti = !1;
  }
  function Pi() {
    var e = Ei;
    return e !== null && (Jl === null ? Jl = e : Jl.push.apply(Jl, e), Ei = null), e;
  }
  function Fi(e) {
    Ei === null ? Ei = [e] : Ei.push(e);
  }
  var Ii = le(null), Li = null, Ri = null;
  function zi(e, t, n) {
    M(Ii, t._currentValue), t._currentValue = n;
  }
  function Bi(e) {
    e._currentValue = Ii.current, ue(Ii);
  }
  function Vi(e, t, n) {
    for (; e !== null;) {
      var r = e.alternate;
      if ((e.childLanes & t) === t ? r !== null && (r.childLanes & t) !== t && (r.childLanes |= t) : (e.childLanes |= t, r !== null && (r.childLanes |= t)), e === n) break;
      e = e.return;
    }
  }
  function Hi(e, t, n, r) {
    var a = e.child;
    for (a !== null && (a.return = e); a !== null;) {
      var o = a.dependencies;
      if (o !== null) {
        var s = a.child;
        o = o.firstContext;
        a: for (; o !== null;) {
          var c = o;
          o = a;
          for (var l = 0; l < t.length; l++) if (c.context === t[l]) {
            o.lanes |= n, c = o.alternate, c !== null && (c.lanes |= n), Vi(o.return, n, e), r || (s = null);
            break a;
          }
          o = c.next;
        }
      } else if (a.tag === 18) {
        if (s = a.return, s === null) throw Error(i(341));
        s.lanes |= n, o = s.alternate, o !== null && (o.lanes |= n), Vi(s, n, e), s = null;
      } else s = a.child;
      if (s !== null) s.return = a;
      else for (s = a; s !== null;) {
        if (s === e) {
          s = null;
          break;
        }
        if (a = s.sibling, a !== null) {
          a.return = s.return, s = a;
          break;
        }
        s = s.return;
      }
      a = s;
    }
  }
  function Ui(e, t, n, r) {
    e = null;
    for (var a = t, o = !1; a !== null;) {
      if (!o) {
        if (a.flags & 524288) o = !0;
        else if (a.flags & 262144) break;
      }
      if (a.tag === 10) {
        var s = a.alternate;
        if (s === null) throw Error(i(387));
        if (s = s.memoizedProps, s !== null) {
          var c = a.type;
          mr(a.pendingProps.value, s.value) || (e === null ? e = [c] : e.push(c));
        }
      } else if (a === me.current) {
        if (s = a.alternate, s === null) throw Error(i(387));
        s.memoizedState.memoizedState !== a.memoizedState.memoizedState && (e === null ? e = [Qf] : e.push(Qf));
      }
      a = a.return;
    }
    e !== null && Hi(t, e, n, r), t.flags |= 262144;
  }
  function Wi(e) {
    for (e = e.firstContext; e !== null;) {
      if (!mr(e.context._currentValue, e.memoizedValue)) return !0;
      e = e.next;
    }
    return !1;
  }
  function Gi(e) {
    Li = e, Ri = null, e = e.dependencies, e !== null && (e.firstContext = null);
  }
  function Ki(e) {
    return Ji(Li, e);
  }
  function qi(e, t) {
    return Li === null && Gi(e), Ji(e, t);
  }
  function Ji(e, t) {
    var n = t._currentValue;
    if (t = {
      context: t,
      memoizedValue: n,
      next: null
    }, Ri === null) {
      if (e === null) throw Error(i(308));
      Ri = t, e.dependencies = {
        lanes: 0,
        firstContext: t
      }, e.flags |= 524288;
    } else Ri = Ri.next = t;
    return n;
  }
  var Yi = typeof AbortController < "u" ? AbortController : function() {
    var e = [], t = this.signal = {
      aborted: !1,
      addEventListener: function(t, n) {
        e.push(n);
      }
    };
    this.abort = function() {
      t.aborted = !0, e.forEach(function(e) {
        return e();
      });
    };
  }, Xi = t.unstable_scheduleCallback, Zi = t.unstable_NormalPriority, Qi = {
    $$typeof: C,
    Consumer: null,
    Provider: null,
    _currentValue: null,
    _currentValue2: null,
    _threadCount: 0
  };
  function Y() {
    return {
      controller: new Yi(),
      data: /* @__PURE__ */ new Map(),
      refCount: 0
    };
  }
  function $i(e) {
    e.refCount--, e.refCount === 0 && Xi(Zi, function() {
      e.controller.abort();
    });
  }
  var ea = null, ta = 0, na = 0, ra = null;
  function ia(e, t) {
    if (ea === null) {
      var n = ea = [];
      ta = 0, na = ld(), ra = {
        status: "pending",
        value: void 0,
        then: function(e) {
          n.push(e);
        }
      };
    }
    return ta++, t.then(X, X), t;
  }
  function X() {
    if (--ta === 0 && ea !== null) {
      ra !== null && (ra.status = "fulfilled");
      var e = ea;
      ea = null, na = 0, ra = null;
      for (var t = 0; t < e.length; t++) (0, e[t])();
    }
  }
  function aa(e, t) {
    var n = [], r = {
      status: "pending",
      value: null,
      reason: null,
      then: function(e) {
        n.push(e);
      }
    };
    return e.then(function() {
      r.status = "fulfilled", r.value = t;
      for (var e = 0; e < n.length; e++) (0, n[e])(t);
    }, function(e) {
      for (r.status = "rejected", r.reason = e, e = 0; e < n.length; e++) (0, n[e])(void 0);
    }), r;
  }
  var oa = k.S;
  k.S = function(e, t) {
    Zl = Ae(), typeof t == "object" && t && typeof t.then == "function" && ia(e, t), oa !== null && oa(e, t);
  };
  var sa = le(null);
  function ca() {
    var e = sa.current;
    return e === null ? Ml.pooledCache : e;
  }
  function la(e, t) {
    t === null ? M(sa, sa.current) : M(sa, t.pool);
  }
  function ua() {
    var e = ca();
    return e === null ? null : {
      parent: Qi._currentValue,
      pool: e
    };
  }
  var da = Error(i(460)), fa = Error(i(474)), pa = Error(i(542)), ma = { then: function() {} };
  function ha(e) {
    return e = e.status, e === "fulfilled" || e === "rejected";
  }
  function ga(e, t, n) {
    switch (n = e[n], n === void 0 ? e.push(t) : n !== t && (t.then(nn, nn), t = n), t.status) {
      case "fulfilled": return t.value;
      case "rejected": throw e = t.reason, ba(e), e;
      default:
        if (typeof t.status == "string") t.then(nn, nn);
        else {
          if (e = Ml, e !== null && 100 < e.shellSuspendCounter) throw Error(i(482));
          e = t, e.status = "pending", e.then(function(e) {
            if (t.status === "pending") {
              var n = t;
              n.status = "fulfilled", n.value = e;
            }
          }, function(e) {
            if (t.status === "pending") {
              var n = t;
              n.status = "rejected", n.reason = e;
            }
          });
        }
        switch (t.status) {
          case "fulfilled": return t.value;
          case "rejected": throw e = t.reason, ba(e), e;
        }
        throw va = t, da;
    }
  }
  function _a(e) {
    try {
      var t = e._init;
      return t(e._payload);
    } catch (e) {
      throw typeof e == "object" && e && typeof e.then == "function" ? (va = e, da) : e;
    }
  }
  var va = null;
  function ya() {
    if (va === null) throw Error(i(459));
    var e = va;
    return va = null, e;
  }
  function ba(e) {
    if (e === da || e === pa) throw Error(i(483));
  }
  var xa = null, Sa = 0;
  function Ca(e) {
    var t = Sa;
    return Sa += 1, xa === null && (xa = []), ga(xa, e, t);
  }
  function wa(e, t) {
    t = t.props.ref, e.ref = t === void 0 ? null : t;
  }
  function Ta(e, t) {
    throw t.$$typeof === g ? Error(i(525)) : (e = Object.prototype.toString.call(t), Error(i(31, e === "[object Object]" ? "object with keys {" + Object.keys(t).join(", ") + "}" : e)));
  }
  function Ea(e) {
    function t(t, n) {
      if (e) {
        var r = t.deletions;
        r === null ? (t.deletions = [n], t.flags |= 16) : r.push(n);
      }
    }
    function n(n, r) {
      if (!e) return null;
      for (; r !== null;) t(n, r), r = r.sibling;
      return null;
    }
    function r(e) {
      for (var t = /* @__PURE__ */ new Map(); e !== null;) e.key === null ? t.set(e.index, e) : t.set(e.key, e), e = e.sibling;
      return t;
    }
    function a(e, t) {
      return e = ei(e, t), e.index = 0, e.sibling = null, e;
    }
    function o(t, n, r) {
      return t.index = r, e ? (r = t.alternate, r === null ? (t.flags |= 67108866, n) : (r = r.index, r < n ? (t.flags |= 67108866, n) : r)) : (t.flags |= 1048576, n);
    }
    function s(t) {
      return e && t.alternate === null && (t.flags |= 67108866), t;
    }
    function c(e, t, n, r) {
      return t === null || t.tag !== 6 ? (t = ii(n, e.mode, r), t.return = e, t) : (t = a(t, n), t.return = e, t);
    }
    function l(e, t, n, r) {
      var i = n.type;
      return i === y ? d(e, t, n.props.children, r, n.key) : t !== null && (t.elementType === i || typeof i == "object" && i && i.$$typeof === O && _a(i) === t.type) ? (t = a(t, n.props), wa(t, n), t.return = e, t) : (t = ni(n.type, n.key, n.props, null, e.mode, r), wa(t, n), t.return = e, t);
    }
    function u(e, t, n, r) {
      return t === null || t.tag !== 4 || t.stateNode.containerInfo !== n.containerInfo || t.stateNode.implementation !== n.implementation ? (t = oi(n, e.mode, r), t.return = e, t) : (t = a(t, n.children || []), t.return = e, t);
    }
    function d(e, t, n, r, i) {
      return t === null || t.tag !== 7 ? (t = ri(n, e.mode, r, i), t.return = e, t) : (t = a(t, n), t.return = e, t);
    }
    function f(e, t, n) {
      if (typeof t == "string" && t !== "" || typeof t == "number" || typeof t == "bigint") return t = ii("" + t, e.mode, n), t.return = e, t;
      if (typeof t == "object" && t) {
        switch (t.$$typeof) {
          case _: return n = ni(t.type, t.key, t.props, null, e.mode, n), wa(n, t), n.return = e, n;
          case v: return t = oi(t, e.mode, n), t.return = e, t;
          case O: return t = _a(t), f(e, t, n);
        }
        if (oe(t) || re(t)) return t = ri(t, e.mode, n, null), t.return = e, t;
        if (typeof t.then == "function") return f(e, Ca(t), n);
        if (t.$$typeof === C) return f(e, qi(e, t), n);
        Ta(e, t);
      }
      return null;
    }
    function p(e, t, n, r) {
      var i = t === null ? null : t.key;
      if (typeof n == "string" && n !== "" || typeof n == "number" || typeof n == "bigint") return i === null ? c(e, t, "" + n, r) : null;
      if (typeof n == "object" && n) {
        switch (n.$$typeof) {
          case _: return n.key === i ? l(e, t, n, r) : null;
          case v: return n.key === i ? u(e, t, n, r) : null;
          case O: return n = _a(n), p(e, t, n, r);
        }
        if (oe(n) || re(n)) return i === null ? d(e, t, n, r, null) : null;
        if (typeof n.then == "function") return p(e, t, Ca(n), r);
        if (n.$$typeof === C) return p(e, t, qi(e, n), r);
        Ta(e, n);
      }
      return null;
    }
    function m(e, t, n, r, i) {
      if (typeof r == "string" && r !== "" || typeof r == "number" || typeof r == "bigint") return e = e.get(n) || null, c(t, e, "" + r, i);
      if (typeof r == "object" && r) {
        switch (r.$$typeof) {
          case _: return e = e.get(r.key === null ? n : r.key) || null, l(t, e, r, i);
          case v: return e = e.get(r.key === null ? n : r.key) || null, u(t, e, r, i);
          case O: return r = _a(r), m(e, t, n, r, i);
        }
        if (oe(r) || re(r)) return e = e.get(n) || null, d(t, e, r, i, null);
        if (typeof r.then == "function") return m(e, t, n, Ca(r), i);
        if (r.$$typeof === C) return m(e, t, n, qi(t, r), i);
        Ta(t, r);
      }
      return null;
    }
    function h(i, a, s, c) {
      for (var l = null, u = null, d = a, h = a = 0, g = null; d !== null && h < s.length; h++) {
        d.index > h ? (g = d, d = null) : g = d.sibling;
        var _ = p(i, d, s[h], c);
        if (_ === null) {
          d === null && (d = g);
          break;
        }
        e && d && _.alternate === null && t(i, d), a = o(_, a, h), u === null ? l = _ : u.sibling = _, u = _, d = g;
      }
      if (h === s.length) return n(i, d), Ti && vi(i, h), l;
      if (d === null) {
        for (; h < s.length; h++) d = f(i, s[h], c), d !== null && (a = o(d, a, h), u === null ? l = d : u.sibling = d, u = d);
        return Ti && vi(i, h), l;
      }
      for (d = r(d); h < s.length; h++) g = m(d, i, h, s[h], c), g !== null && (e && g.alternate !== null && d.delete(g.key === null ? h : g.key), a = o(g, a, h), u === null ? l = g : u.sibling = g, u = g);
      return e && d.forEach(function(e) {
        return t(i, e);
      }), Ti && vi(i, h), l;
    }
    function g(a, s, c, l) {
      if (c == null) throw Error(i(151));
      for (var u = null, d = null, h = s, g = s = 0, _ = null, v = c.next(); h !== null && !v.done; g++, v = c.next()) {
        h.index > g ? (_ = h, h = null) : _ = h.sibling;
        var y = p(a, h, v.value, l);
        if (y === null) {
          h === null && (h = _);
          break;
        }
        e && h && y.alternate === null && t(a, h), s = o(y, s, g), d === null ? u = y : d.sibling = y, d = y, h = _;
      }
      if (v.done) return n(a, h), Ti && vi(a, g), u;
      if (h === null) {
        for (; !v.done; g++, v = c.next()) v = f(a, v.value, l), v !== null && (s = o(v, s, g), d === null ? u = v : d.sibling = v, d = v);
        return Ti && vi(a, g), u;
      }
      for (h = r(h); !v.done; g++, v = c.next()) v = m(h, a, g, v.value, l), v !== null && (e && v.alternate !== null && h.delete(v.key === null ? g : v.key), s = o(v, s, g), d === null ? u = v : d.sibling = v, d = v);
      return e && h.forEach(function(e) {
        return t(a, e);
      }), Ti && vi(a, g), u;
    }
    function b(e, r, o, c) {
      if (typeof o == "object" && o && o.type === y && o.key === null && (o = o.props.children), typeof o == "object" && o) {
        switch (o.$$typeof) {
          case _:
            a: {
              for (var l = o.key; r !== null;) {
                if (r.key === l) {
                  if (l = o.type, l === y) {
                    if (r.tag === 7) {
                      n(e, r.sibling), c = a(r, o.props.children), c.return = e, e = c;
                      break a;
                    }
                  } else if (r.elementType === l || typeof l == "object" && l && l.$$typeof === O && _a(l) === r.type) {
                    n(e, r.sibling), c = a(r, o.props), wa(c, o), c.return = e, e = c;
                    break a;
                  }
                  n(e, r);
                  break;
                } else t(e, r);
                r = r.sibling;
              }
              o.type === y ? (c = ri(o.props.children, e.mode, c, o.key), c.return = e, e = c) : (c = ni(o.type, o.key, o.props, null, e.mode, c), wa(c, o), c.return = e, e = c);
            }
            return s(e);
          case v:
            a: {
              for (l = o.key; r !== null;) {
                if (r.key === l) if (r.tag === 4 && r.stateNode.containerInfo === o.containerInfo && r.stateNode.implementation === o.implementation) {
                  n(e, r.sibling), c = a(r, o.children || []), c.return = e, e = c;
                  break a;
                } else {
                  n(e, r);
                  break;
                }
                else t(e, r);
                r = r.sibling;
              }
              c = oi(o, e.mode, c), c.return = e, e = c;
            }
            return s(e);
          case O: return o = _a(o), b(e, r, o, c);
        }
        if (oe(o)) return h(e, r, o, c);
        if (re(o)) {
          if (l = re(o), typeof l != "function") throw Error(i(150));
          return o = l.call(o), g(e, r, o, c);
        }
        if (typeof o.then == "function") return b(e, r, Ca(o), c);
        if (o.$$typeof === C) return b(e, r, qi(e, o), c);
        Ta(e, o);
      }
      return typeof o == "string" && o !== "" || typeof o == "number" || typeof o == "bigint" ? (o = "" + o, r !== null && r.tag === 6 ? (n(e, r.sibling), c = a(r, o), c.return = e, e = c) : (n(e, r), c = ii(o, e.mode, c), c.return = e, e = c), s(e)) : n(e, r);
    }
    return function(e, t, n, r) {
      try {
        Sa = 0;
        var i = b(e, t, n, r);
        return xa = null, i;
      } catch (t) {
        if (t === da || t === pa) throw t;
        var a = Qr(29, t, null, e.mode);
        return a.lanes = r, a.return = e, a;
      }
    };
  }
  var Da = Ea(!0), Oa = Ea(!1), ka = !1;
  function Aa(e) {
    e.updateQueue = {
      baseState: e.memoizedState,
      firstBaseUpdate: null,
      lastBaseUpdate: null,
      shared: {
        pending: null,
        lanes: 0,
        hiddenCallbacks: null
      },
      callbacks: null
    };
  }
  function ja(e, t) {
    e = e.updateQueue, t.updateQueue === e && (t.updateQueue = {
      baseState: e.baseState,
      firstBaseUpdate: e.firstBaseUpdate,
      lastBaseUpdate: e.lastBaseUpdate,
      shared: e.shared,
      callbacks: null
    });
  }
  function Ma(e) {
    return {
      lane: e,
      tag: 0,
      payload: null,
      callback: null,
      next: null
    };
  }
  function Na(e, t, n) {
    var r = e.updateQueue;
    if (r === null) return null;
    if (r = r.shared, jl & 2) {
      var i = r.pending;
      return i === null ? t.next = t : (t.next = i.next, i.next = t), r.pending = t, t = Yr(e), Jr(e, null, n), t;
    }
    return Gr(e, r, t, n), Yr(e);
  }
  function Pa(e, t, n) {
    if (t = t.updateQueue, t !== null && (t = t.shared, n & 4194048)) {
      var r = t.lanes;
      r &= e.pendingLanes, n |= r, t.lanes = n, it(e, n);
    }
  }
  function Z(e, t) {
    var n = e.updateQueue, r = e.alternate;
    if (r !== null && (r = r.updateQueue, n === r)) {
      var i = null, a = null;
      if (n = n.firstBaseUpdate, n !== null) {
        do {
          var o = {
            lane: n.lane,
            tag: n.tag,
            payload: n.payload,
            callback: null,
            next: null
          };
          a === null ? i = a = o : a = a.next = o, n = n.next;
        } while (n !== null);
        a === null ? i = a = t : a = a.next = t;
      } else i = a = t;
      n = {
        baseState: r.baseState,
        firstBaseUpdate: i,
        lastBaseUpdate: a,
        shared: r.shared,
        callbacks: r.callbacks
      }, e.updateQueue = n;
      return;
    }
    e = n.lastBaseUpdate, e === null ? n.firstBaseUpdate = t : e.next = t, n.lastBaseUpdate = t;
  }
  var Fa = !1;
  function Ia() {
    if (Fa) {
      var e = ra;
      if (e !== null) throw e;
    }
  }
  function La(e, t, n, r) {
    Fa = !1;
    var i = e.updateQueue;
    ka = !1;
    var a = i.firstBaseUpdate, o = i.lastBaseUpdate, s = i.shared.pending;
    if (s !== null) {
      i.shared.pending = null;
      var c = s, l = c.next;
      c.next = null, o === null ? a = l : o.next = l, o = c;
      var u = e.alternate;
      u !== null && (u = u.updateQueue, s = u.lastBaseUpdate, s !== o && (s === null ? u.firstBaseUpdate = l : s.next = l, u.lastBaseUpdate = c));
    }
    if (a !== null) {
      var d = i.baseState;
      o = 0, u = l = c = null, s = a;
      do {
        var f = s.lane & -536870913, p = f !== s.lane;
        if (p ? (Pl & f) === f : (r & f) === f) {
          f !== 0 && f === na && (Fa = !0), u !== null && (u = u.next = {
            lane: 0,
            tag: s.tag,
            payload: s.payload,
            callback: null,
            next: null
          });
          a: {
            var m = e, g = s;
            f = t;
            var _ = n;
            switch (g.tag) {
              case 1:
                if (m = g.payload, typeof m == "function") {
                  d = m.call(_, d, f);
                  break a;
                }
                d = m;
                break a;
              case 3: m.flags = m.flags & -65537 | 128;
              case 0:
                if (m = g.payload, f = typeof m == "function" ? m.call(_, d, f) : m, f == null) break a;
                d = h({}, d, f);
                break a;
              case 2: ka = !0;
            }
          }
          f = s.callback, f !== null && (e.flags |= 64, p && (e.flags |= 8192), p = i.callbacks, p === null ? i.callbacks = [f] : p.push(f));
        } else p = {
          lane: f,
          tag: s.tag,
          payload: s.payload,
          callback: s.callback,
          next: null
        }, u === null ? (l = u = p, c = d) : u = u.next = p, o |= f;
        if (s = s.next, s === null) {
          if (s = i.shared.pending, s === null) break;
          p = s, s = p.next, p.next = null, i.lastBaseUpdate = p, i.shared.pending = null;
        }
      } while (1);
      u === null && (c = d), i.baseState = c, i.firstBaseUpdate = l, i.lastBaseUpdate = u, a === null && (i.shared.lanes = 0), Hl |= o, e.lanes = o, e.memoizedState = d;
    }
  }
  function Ra(e, t) {
    if (typeof e != "function") throw Error(i(191, e));
    e.call(t);
  }
  function za(e, t) {
    var n = e.callbacks;
    if (n !== null) for (e.callbacks = null, e = 0; e < n.length; e++) Ra(n[e], t);
  }
  var Ba = le(null), Va = le(0);
  function Ha(e, t) {
    e = Bl, M(Va, e), M(Ba, t), Bl = e | t.baseLanes;
  }
  function Ua() {
    M(Va, Bl), M(Ba, Ba.current);
  }
  function Wa() {
    Bl = Va.current, ue(Ba), ue(Va);
  }
  var Ga = le(null), Ka = null;
  function qa(e) {
    var t = e.alternate;
    M(Qa, Qa.current & 1), M(Ga, e), Ka === null && (t === null || Ba.current !== null || t.memoizedState !== null) && (Ka = e);
  }
  function Ja(e) {
    M(Qa, Qa.current), M(Ga, e), Ka === null && (Ka = e);
  }
  function Ya(e) {
    e.tag === 22 ? (M(Qa, Qa.current), M(Ga, e), Ka === null && (Ka = e)) : Xa(e);
  }
  function Xa() {
    M(Qa, Qa.current), M(Ga, Ga.current);
  }
  function Za(e) {
    ue(Ga), Ka === e && (Ka = null), ue(Qa);
  }
  var Qa = le(0);
  function $a(e) {
    for (var t = e; t !== null;) {
      if (t.tag === 13) {
        var n = t.memoizedState;
        if (n !== null && (n = n.dehydrated, n === null || af(n) || of(n))) return t;
      } else if (t.tag === 19 && (t.memoizedProps.revealOrder === "forwards" || t.memoizedProps.revealOrder === "backwards" || t.memoizedProps.revealOrder === "unstable_legacy-backwards" || t.memoizedProps.revealOrder === "together")) {
        if (t.flags & 128) return t;
      } else if (t.child !== null) {
        t.child.return = t, t = t.child;
        continue;
      }
      if (t === e) break;
      for (; t.sibling === null;) {
        if (t.return === null || t.return === e) return null;
        t = t.return;
      }
      t.sibling.return = t.return, t = t.sibling;
    }
    return null;
  }
  var eo = 0, to = null, no = null, ro = null, io = !1, ao = !1, oo = !1, so = 0, co = 0, lo = null, uo = 0;
  function fo() {
    throw Error(i(321));
  }
  function po(e, t) {
    if (t === null) return !1;
    for (var n = 0; n < t.length && n < e.length; n++) if (!mr(e[n], t[n])) return !1;
    return !0;
  }
  function mo(e, t, n, r, i, a) {
    return eo = a, to = t, t.memoizedState = null, t.updateQueue = null, t.lanes = 0, k.H = e === null || e.memoizedState === null ? ks : As, oo = !1, a = n(r, i), oo = !1, ao && (a = go(t, n, r, i)), ho(e), a;
  }
  function ho(e) {
    k.H = Os;
    var t = no !== null && no.next !== null;
    if (eo = 0, ro = no = to = null, io = !1, co = 0, lo = null, t) throw Error(i(300));
    e === null || qs || (e = e.dependencies, e !== null && Wi(e) && (qs = !0));
  }
  function go(e, t, n, r) {
    to = e;
    var a = 0;
    do {
      if (ao && (lo = null), co = 0, ao = !1, 25 <= a) throw Error(i(301));
      if (a += 1, ro = no = null, e.updateQueue != null) {
        var o = e.updateQueue;
        o.lastEffect = null, o.events = null, o.stores = null, o.memoCache != null && (o.memoCache.index = 0);
      }
      k.H = js, o = t(n, r);
    } while (ao);
    return o;
  }
  function _o() {
    var e = k.H, t = e.useState()[0];
    return t = typeof t.then == "function" ? wo(t) : t, e = e.useState()[0], (no === null ? null : no.memoizedState) !== e && (to.flags |= 1024), t;
  }
  function vo() {
    var e = so !== 0;
    return so = 0, e;
  }
  function yo(e, t, n) {
    t.updateQueue = e.updateQueue, t.flags &= -2053, e.lanes &= ~n;
  }
  function bo(e) {
    if (io) {
      for (e = e.memoizedState; e !== null;) {
        var t = e.queue;
        t !== null && (t.pending = null), e = e.next;
      }
      io = !1;
    }
    eo = 0, ro = no = to = null, ao = !1, co = so = 0, lo = null;
  }
  function xo() {
    var e = {
      memoizedState: null,
      baseState: null,
      baseQueue: null,
      queue: null,
      next: null
    };
    return ro === null ? to.memoizedState = ro = e : ro = ro.next = e, ro;
  }
  function So() {
    if (no === null) {
      var e = to.alternate;
      e = e === null ? null : e.memoizedState;
    } else e = no.next;
    var t = ro === null ? to.memoizedState : ro.next;
    if (t !== null) ro = t, no = e;
    else {
      if (e === null) throw to.alternate === null ? Error(i(467)) : Error(i(310));
      no = e, e = {
        memoizedState: no.memoizedState,
        baseState: no.baseState,
        baseQueue: no.baseQueue,
        queue: no.queue,
        next: null
      }, ro === null ? to.memoizedState = ro = e : ro = ro.next = e;
    }
    return ro;
  }
  function Co() {
    return {
      lastEffect: null,
      events: null,
      stores: null,
      memoCache: null
    };
  }
  function wo(e) {
    var t = co;
    return co += 1, lo === null && (lo = []), e = ga(lo, e, t), t = to, (ro === null ? t.memoizedState : ro.next) === null && (t = t.alternate, k.H = t === null || t.memoizedState === null ? ks : As), e;
  }
  function To(e) {
    if (typeof e == "object" && e) {
      if (typeof e.then == "function") return wo(e);
      if (e.$$typeof === C) return Ki(e);
    }
    throw Error(i(438, String(e)));
  }
  function Eo(e) {
    var t = null, n = to.updateQueue;
    if (n !== null && (t = n.memoCache), t == null) {
      var r = to.alternate;
      r !== null && (r = r.updateQueue, r !== null && (r = r.memoCache, r != null && (t = {
        data: r.data.map(function(e) {
          return e.slice();
        }),
        index: 0
      })));
    }
    if (t ??= {
      data: [],
      index: 0
    }, n === null && (n = Co(), to.updateQueue = n), n.memoCache = t, n = t.data[t.index], n === void 0) for (n = t.data[t.index] = Array(e), r = 0; r < e; r++) n[r] = te;
    return t.index++, n;
  }
  function Do(e, t) {
    return typeof t == "function" ? t(e) : t;
  }
  function Oo(e) {
    return ko(So(), no, e);
  }
  function ko(e, t, n) {
    var r = e.queue;
    if (r === null) throw Error(i(311));
    r.lastRenderedReducer = n;
    var a = e.baseQueue, o = r.pending;
    if (o !== null) {
      if (a !== null) {
        var s = a.next;
        a.next = o.next, o.next = s;
      }
      t.baseQueue = a = o, r.pending = null;
    }
    if (o = e.baseState, a === null) e.memoizedState = o;
    else {
      t = a.next;
      var c = s = null, l = null, u = t, d = !1;
      do {
        var f = u.lane & -536870913;
        if (f === u.lane ? (eo & f) === f : (Pl & f) === f) {
          var p = u.revertLane;
          if (p === 0) l !== null && (l = l.next = {
            lane: 0,
            revertLane: 0,
            gesture: null,
            action: u.action,
            hasEagerState: u.hasEagerState,
            eagerState: u.eagerState,
            next: null
          }), f === na && (d = !0);
          else if ((eo & p) === p) {
            u = u.next, p === na && (d = !0);
            continue;
          } else f = {
            lane: 0,
            revertLane: u.revertLane,
            gesture: null,
            action: u.action,
            hasEagerState: u.hasEagerState,
            eagerState: u.eagerState,
            next: null
          }, l === null ? (c = l = f, s = o) : l = l.next = f, to.lanes |= p, Hl |= p;
          f = u.action, oo && n(o, f), o = u.hasEagerState ? u.eagerState : n(o, f);
        } else p = {
          lane: f,
          revertLane: u.revertLane,
          gesture: u.gesture,
          action: u.action,
          hasEagerState: u.hasEagerState,
          eagerState: u.eagerState,
          next: null
        }, l === null ? (c = l = p, s = o) : l = l.next = p, to.lanes |= f, Hl |= f;
        u = u.next;
      } while (u !== null && u !== t);
      if (l === null ? s = o : l.next = c, !mr(o, e.memoizedState) && (qs = !0, d && (n = ra, n !== null))) throw n;
      e.memoizedState = o, e.baseState = s, e.baseQueue = l, r.lastRenderedState = o;
    }
    return a === null && (r.lanes = 0), [e.memoizedState, r.dispatch];
  }
  function Ao(e) {
    var t = So(), n = t.queue;
    if (n === null) throw Error(i(311));
    n.lastRenderedReducer = e;
    var r = n.dispatch, a = n.pending, o = t.memoizedState;
    if (a !== null) {
      n.pending = null;
      var s = a = a.next;
      do
        o = e(o, s.action), s = s.next;
      while (s !== a);
      mr(o, t.memoizedState) || (qs = !0), t.memoizedState = o, t.baseQueue === null && (t.baseState = o), n.lastRenderedState = o;
    }
    return [o, r];
  }
  function jo(e, t, n) {
    var r = to, a = So(), o = Ti;
    if (o) {
      if (n === void 0) throw Error(i(407));
      n = n();
    } else n = t();
    var s = !mr((no || a).memoizedState, n);
    if (s && (a.memoizedState = n, qs = !0), a = a.queue, ts(Po.bind(null, r, a, e), [e]), a.getSnapshot !== t || s || ro !== null && ro.memoizedState.tag & 1) {
      if (r.flags |= 2048, Zo(9, { destroy: void 0 }, No.bind(null, r, a, n, t), null), Ml === null) throw Error(i(349));
      o || eo & 127 || Mo(r, t, n);
    }
    return n;
  }
  function Mo(e, t, n) {
    e.flags |= 16384, e = {
      getSnapshot: t,
      value: n
    }, t = to.updateQueue, t === null ? (t = Co(), to.updateQueue = t, t.stores = [e]) : (n = t.stores, n === null ? t.stores = [e] : n.push(e));
  }
  function No(e, t, n, r) {
    t.value = n, t.getSnapshot = r, Fo(t) && Io(e);
  }
  function Po(e, t, n) {
    return n(function() {
      Fo(t) && Io(e);
    });
  }
  function Fo(e) {
    var t = e.getSnapshot;
    e = e.value;
    try {
      var n = t();
      return !mr(e, n);
    } catch {
      return !0;
    }
  }
  function Io(e) {
    var t = qr(e, 2);
    t !== null && fu(t, e, 2);
  }
  function Lo(e) {
    var t = xo();
    if (typeof e == "function") {
      var n = e;
      if (e = n(), oo) {
        Ve(!0);
        try {
          n();
        } finally {
          Ve(!1);
        }
      }
    }
    return t.memoizedState = t.baseState = e, t.queue = {
      pending: null,
      lanes: 0,
      dispatch: null,
      lastRenderedReducer: Do,
      lastRenderedState: e
    }, t;
  }
  function Ro(e, t, n, r) {
    return e.baseState = n, ko(e, no, typeof r == "function" ? r : Do);
  }
  function zo(e, t, n, r, a) {
    if (Ts(e)) throw Error(i(485));
    if (e = t.action, e !== null) {
      var o = {
        payload: a,
        action: e,
        next: null,
        isTransition: !0,
        status: "pending",
        value: null,
        reason: null,
        listeners: [],
        then: function(e) {
          o.listeners.push(e);
        }
      };
      k.T === null ? o.isTransition = !1 : n(!0), r(o), n = t.pending, n === null ? (o.next = t.pending = o, Bo(t, o)) : (o.next = n.next, t.pending = n.next = o);
    }
  }
  function Bo(e, t) {
    var n = t.action, r = t.payload, i = e.state;
    if (t.isTransition) {
      var a = k.T, o = {};
      k.T = o;
      try {
        var s = n(i, r), c = k.S;
        c !== null && c(o, s), Vo(e, t, s);
      } catch (n) {
        Uo(e, t, n);
      } finally {
        a !== null && o.types !== null && (a.types = o.types), k.T = a;
      }
    } else try {
      a = n(i, r), Vo(e, t, a);
    } catch (n) {
      Uo(e, t, n);
    }
  }
  function Vo(e, t, n) {
    typeof n == "object" && n && typeof n.then == "function" ? n.then(function(n) {
      Ho(e, t, n);
    }, function(n) {
      return Uo(e, t, n);
    }) : Ho(e, t, n);
  }
  function Ho(e, t, n) {
    t.status = "fulfilled", t.value = n, Wo(t), e.state = n, t = e.pending, t !== null && (n = t.next, n === t ? e.pending = null : (n = n.next, t.next = n, Bo(e, n)));
  }
  function Uo(e, t, n) {
    var r = e.pending;
    if (e.pending = null, r !== null) {
      r = r.next;
      do
        t.status = "rejected", t.reason = n, Wo(t), t = t.next;
      while (t !== r);
    }
    e.action = null;
  }
  function Wo(e) {
    e = e.listeners;
    for (var t = 0; t < e.length; t++) (0, e[t])();
  }
  function Go(e, t) {
    return t;
  }
  function Ko(e, t) {
    if (Ti) {
      var n = Ml.formState;
      if (n !== null) {
        a: {
          var r = to;
          if (Ti) {
            if (wi) {
              b: {
                for (var i = wi, a = Di; i.nodeType !== 8;) {
                  if (!a) {
                    i = null;
                    break b;
                  }
                  if (i = cf(i.nextSibling), i === null) {
                    i = null;
                    break b;
                  }
                }
                a = i.data, i = a === "F!" || a === "F" ? i : null;
              }
              if (i) {
                wi = cf(i.nextSibling), r = i.data === "F!";
                break a;
              }
            }
            ki(r);
          }
          r = !1;
        }
        r && (t = n[0]);
      }
    }
    return n = xo(), n.memoizedState = n.baseState = t, r = {
      pending: null,
      lanes: 0,
      dispatch: null,
      lastRenderedReducer: Go,
      lastRenderedState: t
    }, n.queue = r, n = Ss.bind(null, to, r), r.dispatch = n, r = Lo(!1), a = ws.bind(null, to, !1, r.queue), r = xo(), i = {
      state: t,
      dispatch: null,
      action: e,
      pending: null
    }, r.queue = i, n = zo.bind(null, to, i, a, n), i.dispatch = n, r.memoizedState = e, [
      t,
      n,
      !1
    ];
  }
  function qo(e) {
    return Jo(So(), no, e);
  }
  function Jo(e, t, n) {
    if (t = ko(e, t, Go)[0], e = Oo(Do)[0], typeof t == "object" && t && typeof t.then == "function") try {
      var r = wo(t);
    } catch (e) {
      throw e === da ? pa : e;
    }
    else r = t;
    t = So();
    var i = t.queue, a = i.dispatch;
    return n !== t.memoizedState && (to.flags |= 2048, Zo(9, { destroy: void 0 }, Yo.bind(null, i, n), null)), [
      r,
      a,
      e
    ];
  }
  function Yo(e, t) {
    e.action = t;
  }
  function Xo(e) {
    var t = So(), n = no;
    if (n !== null) return Jo(t, n, e);
    So(), t = t.memoizedState, n = So();
    var r = n.queue.dispatch;
    return n.memoizedState = e, [
      t,
      r,
      !1
    ];
  }
  function Zo(e, t, n, r) {
    return e = {
      tag: e,
      create: n,
      deps: r,
      inst: t,
      next: null
    }, t = to.updateQueue, t === null && (t = Co(), to.updateQueue = t), n = t.lastEffect, n === null ? t.lastEffect = e.next = e : (r = n.next, n.next = e, e.next = r, t.lastEffect = e), e;
  }
  function Q() {
    return So().memoizedState;
  }
  function Qo(e, t, n, r) {
    var i = xo();
    to.flags |= e, i.memoizedState = Zo(1 | t, { destroy: void 0 }, n, r === void 0 ? null : r);
  }
  function $o(e, t, n, r) {
    var i = So();
    r = r === void 0 ? null : r;
    var a = i.memoizedState.inst;
    no !== null && r !== null && po(r, no.memoizedState.deps) ? i.memoizedState = Zo(t, a, n, r) : (to.flags |= e, i.memoizedState = Zo(1 | t, a, n, r));
  }
  function es(e, t) {
    Qo(8390656, 8, e, t);
  }
  function ts(e, t) {
    $o(2048, 8, e, t);
  }
  function ns(e) {
    to.flags |= 4;
    var t = to.updateQueue;
    if (t === null) t = Co(), to.updateQueue = t, t.events = [e];
    else {
      var n = t.events;
      n === null ? t.events = [e] : n.push(e);
    }
  }
  function rs(e) {
    var t = So().memoizedState;
    return ns({
      ref: t,
      nextImpl: e
    }), function() {
      if (jl & 2) throw Error(i(440));
      return t.impl.apply(void 0, arguments);
    };
  }
  function is(e, t) {
    return $o(4, 2, e, t);
  }
  function as(e, t) {
    return $o(4, 4, e, t);
  }
  function os(e, t) {
    if (typeof t == "function") {
      e = e();
      var n = t(e);
      return function() {
        typeof n == "function" ? n() : t(null);
      };
    }
    if (t != null) return e = e(), t.current = e, function() {
      t.current = null;
    };
  }
  function ss(e, t, n) {
    n = n == null ? null : n.concat([e]), $o(4, 4, os.bind(null, t, e), n);
  }
  function cs() {}
  function ls(e, t) {
    var n = So();
    t = t === void 0 ? null : t;
    var r = n.memoizedState;
    return t !== null && po(t, r[1]) ? r[0] : (n.memoizedState = [e, t], e);
  }
  function us(e, t) {
    var n = So();
    t = t === void 0 ? null : t;
    var r = n.memoizedState;
    if (t !== null && po(t, r[1])) return r[0];
    if (r = e(), oo) {
      Ve(!0);
      try {
        e();
      } finally {
        Ve(!1);
      }
    }
    return n.memoizedState = [r, t], r;
  }
  function ds(e, t, n) {
    return n === void 0 || eo & 1073741824 && !(Pl & 261930) ? e.memoizedState = t : (e.memoizedState = n, e = du(), to.lanes |= e, Hl |= e, n);
  }
  function fs(e, t, n, r) {
    return mr(n, t) ? n : Ba.current === null ? !(eo & 42) || eo & 1073741824 && !(Pl & 261930) ? (qs = !0, e.memoizedState = n) : (e = du(), to.lanes |= e, Hl |= e, t) : (e = ds(e, n, r), mr(e, t) || (qs = !0), e);
  }
  function ps(e, t, n, r, i) {
    var a = A.p;
    A.p = a !== 0 && 8 > a ? a : 8;
    var o = k.T, s = {};
    k.T = s, ws(e, !1, t, n);
    try {
      var c = i(), l = k.S;
      l !== null && l(s, c), typeof c == "object" && c && typeof c.then == "function" ? Cs(e, t, aa(c, r), uu(e)) : Cs(e, t, r, uu(e));
    } catch (n) {
      Cs(e, t, {
        then: function() {},
        status: "rejected",
        reason: n
      }, uu());
    } finally {
      A.p = a, o !== null && s.types !== null && (o.types = s.types), k.T = o;
    }
  }
  function ms() {}
  function hs(e, t, n, r) {
    if (e.tag !== 5) throw Error(i(476));
    var a = gs(e).queue;
    ps(e, a, t, se, n === null ? ms : function() {
      return _s(e), n(r);
    });
  }
  function gs(e) {
    var t = e.memoizedState;
    if (t !== null) return t;
    t = {
      memoizedState: se,
      baseState: se,
      baseQueue: null,
      queue: {
        pending: null,
        lanes: 0,
        dispatch: null,
        lastRenderedReducer: Do,
        lastRenderedState: se
      },
      next: null
    };
    var n = {};
    return t.next = {
      memoizedState: n,
      baseState: n,
      baseQueue: null,
      queue: {
        pending: null,
        lanes: 0,
        dispatch: null,
        lastRenderedReducer: Do,
        lastRenderedState: n
      },
      next: null
    }, e.memoizedState = t, e = e.alternate, e !== null && (e.memoizedState = t), t;
  }
  function _s(e) {
    var t = gs(e);
    t.next === null && (t = e.alternate.memoizedState), Cs(e, t.next.queue, {}, uu());
  }
  function $() {
    return Ki(Qf);
  }
  function vs() {
    return So().memoizedState;
  }
  function ys() {
    return So().memoizedState;
  }
  function bs(e) {
    for (var t = e.return; t !== null;) {
      switch (t.tag) {
        case 24:
        case 3:
          var n = uu();
          e = Ma(n);
          var r = Na(t, e, n);
          r !== null && (fu(r, t, n), Pa(r, t, n)), t = { cache: Y() }, e.payload = t;
          return;
      }
      t = t.return;
    }
  }
  function xs(e, t, n) {
    var r = uu();
    n = {
      lane: r,
      revertLane: 0,
      gesture: null,
      action: n,
      hasEagerState: !1,
      eagerState: null,
      next: null
    }, Ts(e) ? Es(t, n) : (n = Kr(e, t, n, r), n !== null && (fu(n, e, r), Ds(n, t, r)));
  }
  function Ss(e, t, n) {
    Cs(e, t, n, uu());
  }
  function Cs(e, t, n, r) {
    var i = {
      lane: r,
      revertLane: 0,
      gesture: null,
      action: n,
      hasEagerState: !1,
      eagerState: null,
      next: null
    };
    if (Ts(e)) Es(t, i);
    else {
      var a = e.alternate;
      if (e.lanes === 0 && (a === null || a.lanes === 0) && (a = t.lastRenderedReducer, a !== null)) try {
        var o = t.lastRenderedState, s = a(o, n);
        if (i.hasEagerState = !0, i.eagerState = s, mr(s, o)) return Gr(e, t, i, 0), Ml === null && Wr(), !1;
      } catch {}
      if (n = Kr(e, t, i, r), n !== null) return fu(n, e, r), Ds(n, t, r), !0;
    }
    return !1;
  }
  function ws(e, t, n, r) {
    if (r = {
      lane: 2,
      revertLane: ld(),
      gesture: null,
      action: r,
      hasEagerState: !1,
      eagerState: null,
      next: null
    }, Ts(e)) {
      if (t) throw Error(i(479));
    } else t = Kr(e, n, r, 2), t !== null && fu(t, e, 2);
  }
  function Ts(e) {
    var t = e.alternate;
    return e === to || t !== null && t === to;
  }
  function Es(e, t) {
    ao = io = !0;
    var n = e.pending;
    n === null ? t.next = t : (t.next = n.next, n.next = t), e.pending = t;
  }
  function Ds(e, t, n) {
    if (n & 4194048) {
      var r = t.lanes;
      r &= e.pendingLanes, n |= r, t.lanes = n, it(e, n);
    }
  }
  var Os = {
    readContext: Ki,
    use: To,
    useCallback: fo,
    useContext: fo,
    useEffect: fo,
    useImperativeHandle: fo,
    useLayoutEffect: fo,
    useInsertionEffect: fo,
    useMemo: fo,
    useReducer: fo,
    useRef: fo,
    useState: fo,
    useDebugValue: fo,
    useDeferredValue: fo,
    useTransition: fo,
    useSyncExternalStore: fo,
    useId: fo,
    useHostTransitionStatus: fo,
    useFormState: fo,
    useActionState: fo,
    useOptimistic: fo,
    useMemoCache: fo,
    useCacheRefresh: fo
  };
  Os.useEffectEvent = fo;
  var ks = {
    readContext: Ki,
    use: To,
    useCallback: function(e, t) {
      return xo().memoizedState = [e, t === void 0 ? null : t], e;
    },
    useContext: Ki,
    useEffect: es,
    useImperativeHandle: function(e, t, n) {
      n = n == null ? null : n.concat([e]), Qo(4194308, 4, os.bind(null, t, e), n);
    },
    useLayoutEffect: function(e, t) {
      return Qo(4194308, 4, e, t);
    },
    useInsertionEffect: function(e, t) {
      Qo(4, 2, e, t);
    },
    useMemo: function(e, t) {
      var n = xo();
      t = t === void 0 ? null : t;
      var r = e();
      if (oo) {
        Ve(!0);
        try {
          e();
        } finally {
          Ve(!1);
        }
      }
      return n.memoizedState = [r, t], r;
    },
    useReducer: function(e, t, n) {
      var r = xo();
      if (n !== void 0) {
        var i = n(t);
        if (oo) {
          Ve(!0);
          try {
            n(t);
          } finally {
            Ve(!1);
          }
        }
      } else i = t;
      return r.memoizedState = r.baseState = i, e = {
        pending: null,
        lanes: 0,
        dispatch: null,
        lastRenderedReducer: e,
        lastRenderedState: i
      }, r.queue = e, e = e.dispatch = xs.bind(null, to, e), [r.memoizedState, e];
    },
    useRef: function(e) {
      var t = xo();
      return e = { current: e }, t.memoizedState = e;
    },
    useState: function(e) {
      e = Lo(e);
      var t = e.queue, n = Ss.bind(null, to, t);
      return t.dispatch = n, [e.memoizedState, n];
    },
    useDebugValue: cs,
    useDeferredValue: function(e, t) {
      return ds(xo(), e, t);
    },
    useTransition: function() {
      var e = Lo(!1);
      return e = ps.bind(null, to, e.queue, !0, !1), xo().memoizedState = e, [!1, e];
    },
    useSyncExternalStore: function(e, t, n) {
      var r = to, a = xo();
      if (Ti) {
        if (n === void 0) throw Error(i(407));
        n = n();
      } else {
        if (n = t(), Ml === null) throw Error(i(349));
        Pl & 127 || Mo(r, t, n);
      }
      a.memoizedState = n;
      var o = {
        value: n,
        getSnapshot: t
      };
      return a.queue = o, es(Po.bind(null, r, o, e), [e]), r.flags |= 2048, Zo(9, { destroy: void 0 }, No.bind(null, r, o, n, t), null), n;
    },
    useId: function() {
      var e = xo(), t = Ml.identifierPrefix;
      if (Ti) {
        var n = _i, r = gi;
        n = (r & ~(1 << 32 - He(r) - 1)).toString(32) + n, t = "_" + t + "R_" + n, n = so++, 0 < n && (t += "H" + n.toString(32)), t += "_";
      } else n = uo++, t = "_" + t + "r_" + n.toString(32) + "_";
      return e.memoizedState = t;
    },
    useHostTransitionStatus: $,
    useFormState: Ko,
    useActionState: Ko,
    useOptimistic: function(e) {
      var t = xo();
      t.memoizedState = t.baseState = e;
      var n = {
        pending: null,
        lanes: 0,
        dispatch: null,
        lastRenderedReducer: null,
        lastRenderedState: null
      };
      return t.queue = n, t = ws.bind(null, to, !0, n), n.dispatch = t, [e, t];
    },
    useMemoCache: Eo,
    useCacheRefresh: function() {
      return xo().memoizedState = bs.bind(null, to);
    },
    useEffectEvent: function(e) {
      var t = xo(), n = { impl: e };
      return t.memoizedState = n, function() {
        if (jl & 2) throw Error(i(440));
        return n.impl.apply(void 0, arguments);
      };
    }
  }, As = {
    readContext: Ki,
    use: To,
    useCallback: ls,
    useContext: Ki,
    useEffect: ts,
    useImperativeHandle: ss,
    useInsertionEffect: is,
    useLayoutEffect: as,
    useMemo: us,
    useReducer: Oo,
    useRef: Q,
    useState: function() {
      return Oo(Do);
    },
    useDebugValue: cs,
    useDeferredValue: function(e, t) {
      return fs(So(), no.memoizedState, e, t);
    },
    useTransition: function() {
      var e = Oo(Do)[0], t = So().memoizedState;
      return [typeof e == "boolean" ? e : wo(e), t];
    },
    useSyncExternalStore: jo,
    useId: vs,
    useHostTransitionStatus: $,
    useFormState: qo,
    useActionState: qo,
    useOptimistic: function(e, t) {
      return Ro(So(), no, e, t);
    },
    useMemoCache: Eo,
    useCacheRefresh: ys
  };
  As.useEffectEvent = rs;
  var js = {
    readContext: Ki,
    use: To,
    useCallback: ls,
    useContext: Ki,
    useEffect: ts,
    useImperativeHandle: ss,
    useInsertionEffect: is,
    useLayoutEffect: as,
    useMemo: us,
    useReducer: Ao,
    useRef: Q,
    useState: function() {
      return Ao(Do);
    },
    useDebugValue: cs,
    useDeferredValue: function(e, t) {
      var n = So();
      return no === null ? ds(n, e, t) : fs(n, no.memoizedState, e, t);
    },
    useTransition: function() {
      var e = Ao(Do)[0], t = So().memoizedState;
      return [typeof e == "boolean" ? e : wo(e), t];
    },
    useSyncExternalStore: jo,
    useId: vs,
    useHostTransitionStatus: $,
    useFormState: Xo,
    useActionState: Xo,
    useOptimistic: function(e, t) {
      var n = So();
      return no === null ? (n.baseState = e, [e, n.queue.dispatch]) : Ro(n, no, e, t);
    },
    useMemoCache: Eo,
    useCacheRefresh: ys
  };
  js.useEffectEvent = rs;
  function Ms(e, t, n, r) {
    t = e.memoizedState, n = n(r, t), n = n == null ? t : h({}, t, n), e.memoizedState = n, e.lanes === 0 && (e.updateQueue.baseState = n);
  }
  var Ns = {
    enqueueSetState: function(e, t, n) {
      e = e._reactInternals;
      var r = uu(), i = Ma(r);
      i.payload = t, n != null && (i.callback = n), t = Na(e, i, r), t !== null && (fu(t, e, r), Pa(t, e, r));
    },
    enqueueReplaceState: function(e, t, n) {
      e = e._reactInternals;
      var r = uu(), i = Ma(r);
      i.tag = 1, i.payload = t, n != null && (i.callback = n), t = Na(e, i, r), t !== null && (fu(t, e, r), Pa(t, e, r));
    },
    enqueueForceUpdate: function(e, t) {
      e = e._reactInternals;
      var n = uu(), r = Ma(n);
      r.tag = 2, t != null && (r.callback = t), t = Na(e, r, n), t !== null && (fu(t, e, n), Pa(t, e, n));
    }
  };
  function Ps(e, t, n, r, i, a, o) {
    return e = e.stateNode, typeof e.shouldComponentUpdate == "function" ? e.shouldComponentUpdate(r, a, o) : t.prototype && t.prototype.isPureReactComponent ? !hr(n, r) || !hr(i, a) : !0;
  }
  function Fs(e, t, n, r) {
    e = t.state, typeof t.componentWillReceiveProps == "function" && t.componentWillReceiveProps(n, r), typeof t.UNSAFE_componentWillReceiveProps == "function" && t.UNSAFE_componentWillReceiveProps(n, r), t.state !== e && Ns.enqueueReplaceState(t, t.state, null);
  }
  function Is(e, t) {
    var n = t;
    if ("ref" in t) for (var r in n = {}, t) r !== "ref" && (n[r] = t[r]);
    if (e = e.defaultProps) for (var i in n === t && (n = h({}, n)), e) n[i] === void 0 && (n[i] = e[i]);
    return n;
  }
  function Ls(e) {
    Br(e);
  }
  function Rs(e) {
    console.error(e);
  }
  function zs(e) {
    Br(e);
  }
  function Bs(e, t) {
    try {
      var n = e.onUncaughtError;
      n(t.value, { componentStack: t.stack });
    } catch (e) {
      setTimeout(function() {
        throw e;
      });
    }
  }
  function Vs(e, t, n) {
    try {
      var r = e.onCaughtError;
      r(n.value, {
        componentStack: n.stack,
        errorBoundary: t.tag === 1 ? t.stateNode : null
      });
    } catch (e) {
      setTimeout(function() {
        throw e;
      });
    }
  }
  function Hs(e, t, n) {
    return n = Ma(n), n.tag = 3, n.payload = { element: null }, n.callback = function() {
      Bs(e, t);
    }, n;
  }
  function Us(e) {
    return e = Ma(e), e.tag = 3, e;
  }
  function Ws(e, t, n, r) {
    var i = n.type.getDerivedStateFromError;
    if (typeof i == "function") {
      var a = r.value;
      e.payload = function() {
        return i(a);
      }, e.callback = function() {
        Vs(t, n, r);
      };
    }
    var o = n.stateNode;
    o !== null && typeof o.componentDidCatch == "function" && (e.callback = function() {
      Vs(t, n, r), typeof i != "function" && (eu === null ? eu = /* @__PURE__ */ new Set([this]) : eu.add(this));
      var e = r.stack;
      this.componentDidCatch(r.value, { componentStack: e === null ? "" : e });
    });
  }
  function Gs(e, t, n, r, a) {
    if (n.flags |= 32768, typeof r == "object" && r && typeof r.then == "function") {
      if (t = n.alternate, t !== null && Ui(t, n, a, !0), n = Ga.current, n !== null) {
        switch (n.tag) {
          case 31:
          case 13: return Ka === null ? wu() : n.alternate === null && Vl === 0 && (Vl = 3), n.flags &= -257, n.flags |= 65536, n.lanes = a, r === ma ? n.flags |= 16384 : (t = n.updateQueue, t === null ? n.updateQueue = /* @__PURE__ */ new Set([r]) : t.add(r), Uu(e, r, a)), !1;
          case 22: return n.flags |= 65536, r === ma ? n.flags |= 16384 : (t = n.updateQueue, t === null ? (t = {
            transitions: null,
            markerInstances: null,
            retryQueue: /* @__PURE__ */ new Set([r])
          }, n.updateQueue = t) : (n = t.retryQueue, n === null ? t.retryQueue = /* @__PURE__ */ new Set([r]) : n.add(r)), Uu(e, r, a)), !1;
        }
        throw Error(i(435, n.tag));
      }
      return Uu(e, r, a), wu(), !1;
    }
    if (Ti) return t = Ga.current, t === null ? (r !== Oi && (t = Error(i(423), { cause: r }), Fi(ci(t, n))), e = e.current.alternate, e.flags |= 65536, a &= -a, e.lanes |= a, r = ci(r, n), a = Hs(e.stateNode, r, a), Z(e, a), Vl !== 4 && (Vl = 2)) : (!(t.flags & 65536) && (t.flags |= 256), t.flags |= 65536, t.lanes = a, r !== Oi && (e = Error(i(422), { cause: r }), Fi(ci(e, n)))), !1;
    var o = Error(i(520), { cause: r });
    if (o = ci(o, n), ql === null ? ql = [o] : ql.push(o), Vl !== 4 && (Vl = 2), t === null) return !0;
    r = ci(r, n), n = t;
    do {
      switch (n.tag) {
        case 3: return n.flags |= 65536, e = a & -a, n.lanes |= e, e = Hs(n.stateNode, r, e), Z(n, e), !1;
        case 1: if (t = n.type, o = n.stateNode, !(n.flags & 128) && (typeof t.getDerivedStateFromError == "function" || o !== null && typeof o.componentDidCatch == "function" && (eu === null || !eu.has(o)))) return n.flags |= 65536, a &= -a, n.lanes |= a, a = Us(a), Ws(a, e, n, r), Z(n, a), !1;
      }
      n = n.return;
    } while (n !== null);
    return !1;
  }
  var Ks = Error(i(461)), qs = !1;
  function Js(e, t, n, r) {
    t.child = e === null ? Oa(t, null, n, r) : Da(t, e.child, n, r);
  }
  function Ys(e, t, n, r, i) {
    n = n.render;
    var a = t.ref;
    if ("ref" in r) {
      var o = {};
      for (var s in r) s !== "ref" && (o[s] = r[s]);
    } else o = r;
    return Gi(t), r = mo(e, t, n, o, a, i), s = vo(), e !== null && !qs ? (yo(e, t, i), yc(e, t, i)) : (Ti && s && bi(t), t.flags |= 1, Js(e, t, r, i), t.child);
  }
  function Xs(e, t, n, r, i) {
    if (e === null) {
      var a = n.type;
      return typeof a == "function" && !$r(a) && a.defaultProps === void 0 && n.compare === null ? (t.tag = 15, t.type = a, Zs(e, t, a, r, i)) : (e = ni(n.type, null, r, t, t.mode, i), e.ref = t.ref, e.return = t, t.child = e);
    }
    if (a = e.child, !bc(e, i)) {
      var o = a.memoizedProps;
      if (n = n.compare, n = n === null ? hr : n, n(o, r) && e.ref === t.ref) return yc(e, t, i);
    }
    return t.flags |= 1, e = ei(a, r), e.ref = t.ref, e.return = t, t.child = e;
  }
  function Zs(e, t, n, r, i) {
    if (e !== null) {
      var a = e.memoizedProps;
      if (hr(a, r) && e.ref === t.ref) if (qs = !1, t.pendingProps = r = a, bc(e, i)) e.flags & 131072 && (qs = !0);
      else return t.lanes = e.lanes, yc(e, t, i);
    }
    return ac(e, t, n, r, i);
  }
  function Qs(e, t, n, r) {
    var i = r.children, a = e === null ? null : e.memoizedState;
    if (e === null && t.stateNode === null && (t.stateNode = {
      _visibility: 1,
      _pendingMarkers: null,
      _retryCache: null,
      _transitions: null
    }), r.mode === "hidden") {
      if (t.flags & 128) {
        if (a = a === null ? n : a.baseLanes | n, e !== null) {
          for (r = t.child = e.child, i = 0; r !== null;) i = i | r.lanes | r.childLanes, r = r.sibling;
          r = i & ~a;
        } else r = 0, t.child = null;
        return ec(e, t, a, n, r);
      }
      if (n & 536870912) t.memoizedState = {
        baseLanes: 0,
        cachePool: null
      }, e !== null && la(t, a === null ? null : a.cachePool), a === null ? Ua() : Ha(t, a), Ya(t);
      else return r = t.lanes = 536870912, ec(e, t, a === null ? n : a.baseLanes | n, n, r);
    } else a === null ? (e !== null && la(t, null), Ua(), Xa(t)) : (la(t, a.cachePool), Ha(t, a), Xa(t), t.memoizedState = null);
    return Js(e, t, i, n), t.child;
  }
  function $s(e, t) {
    return e !== null && e.tag === 22 || t.stateNode !== null || (t.stateNode = {
      _visibility: 1,
      _pendingMarkers: null,
      _retryCache: null,
      _transitions: null
    }), t.sibling;
  }
  function ec(e, t, n, r, i) {
    var a = ca();
    return a = a === null ? null : {
      parent: Qi._currentValue,
      pool: a
    }, t.memoizedState = {
      baseLanes: n,
      cachePool: a
    }, e !== null && la(t, null), Ua(), Ya(t), e !== null && Ui(e, t, r, !0), t.childLanes = i, null;
  }
  function tc(e, t) {
    return t = mc({
      mode: t.mode,
      children: t.children
    }, e.mode), t.ref = e.ref, e.child = t, t.return = e, t;
  }
  function nc(e, t, n) {
    return Da(t, e.child, null, n), e = tc(t, t.pendingProps), e.flags |= 2, Za(t), t.memoizedState = null, e;
  }
  function rc(e, t, n) {
    var r = t.pendingProps, a = (t.flags & 128) != 0;
    if (t.flags &= -129, e === null) {
      if (Ti) {
        if (r.mode === "hidden") return e = tc(t, r), t.lanes = 536870912, $s(null, e);
        if (Ja(t), (e = wi) ? (e = rf(e, Di), e = e !== null && e.data === "&" ? e : null, e !== null && (t.memoizedState = {
          dehydrated: e,
          treeContext: hi === null ? null : {
            id: gi,
            overflow: _i
          },
          retryLane: 536870912,
          hydrationErrors: null
        }, n = ai(e), n.return = t, t.child = n, Ci = t, wi = null)) : e = null, e === null) throw ki(t);
        return t.lanes = 536870912, null;
      }
      return tc(t, r);
    }
    var o = e.memoizedState;
    if (o !== null) {
      var s = o.dehydrated;
      if (Ja(t), a) if (t.flags & 256) t.flags &= -257, t = nc(e, t, n);
      else if (t.memoizedState !== null) t.child = e.child, t.flags |= 128, t = null;
      else throw Error(i(558));
      else if (qs || Ui(e, t, n, !1), a = (n & e.childLanes) !== 0, qs || a) {
        if (r = Ml, r !== null && (s = at(r, n), s !== 0 && s !== o.retryLane)) throw o.retryLane = s, qr(e, s), fu(r, e, s), Ks;
        wu(), t = nc(e, t, n);
      } else e = o.treeContext, wi = cf(s.nextSibling), Ci = t, Ti = !0, Ei = null, Di = !1, e !== null && Si(t, e), t = tc(t, r), t.flags |= 4096;
      return t;
    }
    return e = ei(e.child, {
      mode: r.mode,
      children: r.children
    }), e.ref = t.ref, t.child = e, e.return = t, e;
  }
  function ic(e, t) {
    var n = t.ref;
    if (n === null) e !== null && e.ref !== null && (t.flags |= 4194816);
    else {
      if (typeof n != "function" && typeof n != "object") throw Error(i(284));
      (e === null || e.ref !== n) && (t.flags |= 4194816);
    }
  }
  function ac(e, t, n, r, i) {
    return Gi(t), n = mo(e, t, n, r, void 0, i), r = vo(), e !== null && !qs ? (yo(e, t, i), yc(e, t, i)) : (Ti && r && bi(t), t.flags |= 1, Js(e, t, n, i), t.child);
  }
  function oc(e, t, n, r, i, a) {
    return Gi(t), t.updateQueue = null, n = go(t, r, n, i), ho(e), r = vo(), e !== null && !qs ? (yo(e, t, a), yc(e, t, a)) : (Ti && r && bi(t), t.flags |= 1, Js(e, t, n, a), t.child);
  }
  function sc(e, t, n, r, i) {
    if (Gi(t), t.stateNode === null) {
      var a = Xr, o = n.contextType;
      typeof o == "object" && o && (a = Ki(o)), a = new n(r, a), t.memoizedState = a.state !== null && a.state !== void 0 ? a.state : null, a.updater = Ns, t.stateNode = a, a._reactInternals = t, a = t.stateNode, a.props = r, a.state = t.memoizedState, a.refs = {}, Aa(t), o = n.contextType, a.context = typeof o == "object" && o ? Ki(o) : Xr, a.state = t.memoizedState, o = n.getDerivedStateFromProps, typeof o == "function" && (Ms(t, n, o, r), a.state = t.memoizedState), typeof n.getDerivedStateFromProps == "function" || typeof a.getSnapshotBeforeUpdate == "function" || typeof a.UNSAFE_componentWillMount != "function" && typeof a.componentWillMount != "function" || (o = a.state, typeof a.componentWillMount == "function" && a.componentWillMount(), typeof a.UNSAFE_componentWillMount == "function" && a.UNSAFE_componentWillMount(), o !== a.state && Ns.enqueueReplaceState(a, a.state, null), La(t, r, a, i), Ia(), a.state = t.memoizedState), typeof a.componentDidMount == "function" && (t.flags |= 4194308), r = !0;
    } else if (e === null) {
      a = t.stateNode;
      var s = t.memoizedProps, c = Is(n, s);
      a.props = c;
      var l = a.context, u = n.contextType;
      o = Xr, typeof u == "object" && u && (o = Ki(u));
      var d = n.getDerivedStateFromProps;
      u = typeof d == "function" || typeof a.getSnapshotBeforeUpdate == "function", s = t.pendingProps !== s, u || typeof a.UNSAFE_componentWillReceiveProps != "function" && typeof a.componentWillReceiveProps != "function" || (s || l !== o) && Fs(t, a, r, o), ka = !1;
      var f = t.memoizedState;
      a.state = f, La(t, r, a, i), Ia(), l = t.memoizedState, s || f !== l || ka ? (typeof d == "function" && (Ms(t, n, d, r), l = t.memoizedState), (c = ka || Ps(t, n, c, r, f, l, o)) ? (u || typeof a.UNSAFE_componentWillMount != "function" && typeof a.componentWillMount != "function" || (typeof a.componentWillMount == "function" && a.componentWillMount(), typeof a.UNSAFE_componentWillMount == "function" && a.UNSAFE_componentWillMount()), typeof a.componentDidMount == "function" && (t.flags |= 4194308)) : (typeof a.componentDidMount == "function" && (t.flags |= 4194308), t.memoizedProps = r, t.memoizedState = l), a.props = r, a.state = l, a.context = o, r = c) : (typeof a.componentDidMount == "function" && (t.flags |= 4194308), r = !1);
    } else {
      a = t.stateNode, ja(e, t), o = t.memoizedProps, u = Is(n, o), a.props = u, d = t.pendingProps, f = a.context, l = n.contextType, c = Xr, typeof l == "object" && l && (c = Ki(l)), s = n.getDerivedStateFromProps, (l = typeof s == "function" || typeof a.getSnapshotBeforeUpdate == "function") || typeof a.UNSAFE_componentWillReceiveProps != "function" && typeof a.componentWillReceiveProps != "function" || (o !== d || f !== c) && Fs(t, a, r, c), ka = !1, f = t.memoizedState, a.state = f, La(t, r, a, i), Ia();
      var p = t.memoizedState;
      o !== d || f !== p || ka || e !== null && e.dependencies !== null && Wi(e.dependencies) ? (typeof s == "function" && (Ms(t, n, s, r), p = t.memoizedState), (u = ka || Ps(t, n, u, r, f, p, c) || e !== null && e.dependencies !== null && Wi(e.dependencies)) ? (l || typeof a.UNSAFE_componentWillUpdate != "function" && typeof a.componentWillUpdate != "function" || (typeof a.componentWillUpdate == "function" && a.componentWillUpdate(r, p, c), typeof a.UNSAFE_componentWillUpdate == "function" && a.UNSAFE_componentWillUpdate(r, p, c)), typeof a.componentDidUpdate == "function" && (t.flags |= 4), typeof a.getSnapshotBeforeUpdate == "function" && (t.flags |= 1024)) : (typeof a.componentDidUpdate != "function" || o === e.memoizedProps && f === e.memoizedState || (t.flags |= 4), typeof a.getSnapshotBeforeUpdate != "function" || o === e.memoizedProps && f === e.memoizedState || (t.flags |= 1024), t.memoizedProps = r, t.memoizedState = p), a.props = r, a.state = p, a.context = c, r = u) : (typeof a.componentDidUpdate != "function" || o === e.memoizedProps && f === e.memoizedState || (t.flags |= 4), typeof a.getSnapshotBeforeUpdate != "function" || o === e.memoizedProps && f === e.memoizedState || (t.flags |= 1024), r = !1);
    }
    return a = r, ic(e, t), r = (t.flags & 128) != 0, a || r ? (a = t.stateNode, n = r && typeof n.getDerivedStateFromError != "function" ? null : a.render(), t.flags |= 1, e !== null && r ? (t.child = Da(t, e.child, null, i), t.child = Da(t, null, n, i)) : Js(e, t, n, i), t.memoizedState = a.state, e = t.child) : e = yc(e, t, i), e;
  }
  function cc(e, t, n, r) {
    return Ni(), t.flags |= 256, Js(e, t, n, r), t.child;
  }
  var lc = {
    dehydrated: null,
    treeContext: null,
    retryLane: 0,
    hydrationErrors: null
  };
  function uc(e) {
    return {
      baseLanes: e,
      cachePool: ua()
    };
  }
  function dc(e, t, n) {
    return e = e === null ? 0 : e.childLanes & ~n, t && (e |= Gl), e;
  }
  function fc(e, t, n) {
    var r = t.pendingProps, a = !1, o = (t.flags & 128) != 0, s;
    if ((s = o) || (s = e !== null && e.memoizedState === null ? !1 : (Qa.current & 2) != 0), s && (a = !0, t.flags &= -129), s = (t.flags & 32) != 0, t.flags &= -33, e === null) {
      if (Ti) {
        if (a ? qa(t) : Xa(t), (e = wi) ? (e = rf(e, Di), e = e !== null && e.data !== "&" ? e : null, e !== null && (t.memoizedState = {
          dehydrated: e,
          treeContext: hi === null ? null : {
            id: gi,
            overflow: _i
          },
          retryLane: 536870912,
          hydrationErrors: null
        }, n = ai(e), n.return = t, t.child = n, Ci = t, wi = null)) : e = null, e === null) throw ki(t);
        return of(e) ? t.lanes = 32 : t.lanes = 536870912, null;
      }
      var c = r.children;
      return r = r.fallback, a ? (Xa(t), a = t.mode, c = mc({
        mode: "hidden",
        children: c
      }, a), r = ri(r, a, n, null), c.return = t, r.return = t, c.sibling = r, t.child = c, r = t.child, r.memoizedState = uc(n), r.childLanes = dc(e, s, n), t.memoizedState = lc, $s(null, r)) : (qa(t), pc(t, c));
    }
    var l = e.memoizedState;
    if (l !== null && (c = l.dehydrated, c !== null)) {
      if (o) t.flags & 256 ? (qa(t), t.flags &= -257, t = hc(e, t, n)) : t.memoizedState === null ? (Xa(t), c = r.fallback, a = t.mode, r = mc({
        mode: "visible",
        children: r.children
      }, a), c = ri(c, a, n, null), c.flags |= 2, r.return = t, c.return = t, r.sibling = c, t.child = r, Da(t, e.child, null, n), r = t.child, r.memoizedState = uc(n), r.childLanes = dc(e, s, n), t.memoizedState = lc, t = $s(null, r)) : (Xa(t), t.child = e.child, t.flags |= 128, t = null);
      else if (qa(t), of(c)) {
        if (s = c.nextSibling && c.nextSibling.dataset, s) var u = s.dgst;
        s = u, r = Error(i(419)), r.stack = "", r.digest = s, Fi({
          value: r,
          source: null,
          stack: null
        }), t = hc(e, t, n);
      } else if (qs || Ui(e, t, n, !1), s = (n & e.childLanes) !== 0, qs || s) {
        if (s = Ml, s !== null && (r = at(s, n), r !== 0 && r !== l.retryLane)) throw l.retryLane = r, qr(e, r), fu(s, e, r), Ks;
        af(c) || wu(), t = hc(e, t, n);
      } else af(c) ? (t.flags |= 192, t.child = e.child, t = null) : (e = l.treeContext, wi = cf(c.nextSibling), Ci = t, Ti = !0, Ei = null, Di = !1, e !== null && Si(t, e), t = pc(t, r.children), t.flags |= 4096);
      return t;
    }
    return a ? (Xa(t), c = r.fallback, a = t.mode, l = e.child, u = l.sibling, r = ei(l, {
      mode: "hidden",
      children: r.children
    }), r.subtreeFlags = l.subtreeFlags & 65011712, u === null ? (c = ri(c, a, n, null), c.flags |= 2) : c = ei(u, c), c.return = t, r.return = t, r.sibling = c, t.child = r, $s(null, r), r = t.child, c = e.child.memoizedState, c === null ? c = uc(n) : (a = c.cachePool, a === null ? a = ua() : (l = Qi._currentValue, a = a.parent === l ? a : {
      parent: l,
      pool: l
    }), c = {
      baseLanes: c.baseLanes | n,
      cachePool: a
    }), r.memoizedState = c, r.childLanes = dc(e, s, n), t.memoizedState = lc, $s(e.child, r)) : (qa(t), n = e.child, e = n.sibling, n = ei(n, {
      mode: "visible",
      children: r.children
    }), n.return = t, n.sibling = null, e !== null && (s = t.deletions, s === null ? (t.deletions = [e], t.flags |= 16) : s.push(e)), t.child = n, t.memoizedState = null, n);
  }
  function pc(e, t) {
    return t = mc({
      mode: "visible",
      children: t
    }, e.mode), t.return = e, e.child = t;
  }
  function mc(e, t) {
    return e = Qr(22, e, null, t), e.lanes = 0, e;
  }
  function hc(e, t, n) {
    return Da(t, e.child, null, n), e = pc(t, t.pendingProps.children), e.flags |= 2, t.memoizedState = null, e;
  }
  function gc(e, t, n) {
    e.lanes |= t;
    var r = e.alternate;
    r !== null && (r.lanes |= t), Vi(e.return, t, n);
  }
  function _c(e, t, n, r, i, a) {
    var o = e.memoizedState;
    o === null ? e.memoizedState = {
      isBackwards: t,
      rendering: null,
      renderingStartTime: 0,
      last: r,
      tail: n,
      tailMode: i,
      treeForkCount: a
    } : (o.isBackwards = t, o.rendering = null, o.renderingStartTime = 0, o.last = r, o.tail = n, o.tailMode = i, o.treeForkCount = a);
  }
  function vc(e, t, n) {
    var r = t.pendingProps, i = r.revealOrder, a = r.tail;
    r = r.children;
    var o = Qa.current, s = (o & 2) != 0;
    if (s ? (o = o & 1 | 2, t.flags |= 128) : o &= 1, M(Qa, o), Js(e, t, r, n), r = Ti ? fi : 0, !s && e !== null && e.flags & 128) a: for (e = t.child; e !== null;) {
      if (e.tag === 13) e.memoizedState !== null && gc(e, n, t);
      else if (e.tag === 19) gc(e, n, t);
      else if (e.child !== null) {
        e.child.return = e, e = e.child;
        continue;
      }
      if (e === t) break a;
      for (; e.sibling === null;) {
        if (e.return === null || e.return === t) break a;
        e = e.return;
      }
      e.sibling.return = e.return, e = e.sibling;
    }
    switch (i) {
      case "forwards":
        for (n = t.child, i = null; n !== null;) e = n.alternate, e !== null && $a(e) === null && (i = n), n = n.sibling;
        n = i, n === null ? (i = t.child, t.child = null) : (i = n.sibling, n.sibling = null), _c(t, !1, i, n, a, r);
        break;
      case "backwards":
      case "unstable_legacy-backwards":
        for (n = null, i = t.child, t.child = null; i !== null;) {
          if (e = i.alternate, e !== null && $a(e) === null) {
            t.child = i;
            break;
          }
          e = i.sibling, i.sibling = n, n = i, i = e;
        }
        _c(t, !0, n, null, a, r);
        break;
      case "together":
        _c(t, !1, null, null, void 0, r);
        break;
      default: t.memoizedState = null;
    }
    return t.child;
  }
  function yc(e, t, n) {
    if (e !== null && (t.dependencies = e.dependencies), Hl |= t.lanes, (n & t.childLanes) === 0) if (e !== null) {
      if (Ui(e, t, n, !1), (n & t.childLanes) === 0) return null;
    } else return null;
    if (e !== null && t.child !== e.child) throw Error(i(153));
    if (t.child !== null) {
      for (e = t.child, n = ei(e, e.pendingProps), t.child = n, n.return = t; e.sibling !== null;) e = e.sibling, n = n.sibling = ei(e, e.pendingProps), n.return = t;
      n.sibling = null;
    }
    return t.child;
  }
  function bc(e, t) {
    return (e.lanes & t) === 0 ? (e = e.dependencies, !!(e !== null && Wi(e))) : !0;
  }
  function xc(e, t, n) {
    switch (t.tag) {
      case 3:
        he(t, t.stateNode.containerInfo), zi(t, Qi, e.memoizedState.cache), Ni();
        break;
      case 27:
      case 5:
        _e(t);
        break;
      case 4:
        he(t, t.stateNode.containerInfo);
        break;
      case 10:
        zi(t, t.type, t.memoizedProps.value);
        break;
      case 31:
        if (t.memoizedState !== null) return t.flags |= 128, Ja(t), null;
        break;
      case 13:
        var r = t.memoizedState;
        if (r !== null) return r.dehydrated === null ? (n & t.child.childLanes) === 0 ? (qa(t), e = yc(e, t, n), e === null ? null : e.sibling) : fc(e, t, n) : (qa(t), t.flags |= 128, null);
        qa(t);
        break;
      case 19:
        var i = (e.flags & 128) != 0;
        if (r = (n & t.childLanes) !== 0, r ||= (Ui(e, t, n, !1), (n & t.childLanes) !== 0), i) {
          if (r) return vc(e, t, n);
          t.flags |= 128;
        }
        if (i = t.memoizedState, i !== null && (i.rendering = null, i.tail = null, i.lastEffect = null), M(Qa, Qa.current), r) break;
        return null;
      case 22: return t.lanes = 0, Qs(e, t, n, t.pendingProps);
      case 24: zi(t, Qi, e.memoizedState.cache);
    }
    return yc(e, t, n);
  }
  function Sc(e, t, n) {
    if (e !== null) if (e.memoizedProps !== t.pendingProps) qs = !0;
    else {
      if (!bc(e, n) && !(t.flags & 128)) return qs = !1, xc(e, t, n);
      qs = !!(e.flags & 131072);
    }
    else qs = !1, Ti && t.flags & 1048576 && yi(t, fi, t.index);
    switch (t.lanes = 0, t.tag) {
      case 16:
        a: {
          var r = t.pendingProps;
          if (e = _a(t.elementType), t.type = e, typeof e == "function") $r(e) ? (r = Is(e, r), t.tag = 1, t = sc(null, t, e, r, n)) : (t.tag = 0, t = ac(null, t, e, r, n));
          else {
            if (e != null) {
              var a = e.$$typeof;
              if (a === w) {
                t.tag = 11, t = Ys(null, t, e, r, n);
                break a;
              } else if (a === D) {
                t.tag = 14, t = Xs(null, t, e, r, n);
                break a;
              }
            }
            throw t = ae(e) || e, Error(i(306, t, ""));
          }
        }
        return t;
      case 0: return ac(e, t, t.type, t.pendingProps, n);
      case 1: return r = t.type, a = Is(r, t.pendingProps), sc(e, t, r, a, n);
      case 3:
        a: {
          if (he(t, t.stateNode.containerInfo), e === null) throw Error(i(387));
          r = t.pendingProps;
          var o = t.memoizedState;
          a = o.element, ja(e, t), La(t, r, null, n);
          var s = t.memoizedState;
          if (r = s.cache, zi(t, Qi, r), r !== o.cache && Hi(t, [Qi], n, !0), Ia(), r = s.element, o.isDehydrated) if (o = {
            element: r,
            isDehydrated: !1,
            cache: s.cache
          }, t.updateQueue.baseState = o, t.memoizedState = o, t.flags & 256) {
            t = cc(e, t, r, n);
            break a;
          } else if (r !== a) {
            a = ci(Error(i(424)), t), Fi(a), t = cc(e, t, r, n);
            break a;
          } else {
            switch (e = t.stateNode.containerInfo, e.nodeType) {
              case 9:
                e = e.body;
                break;
              default: e = e.nodeName === "HTML" ? e.ownerDocument.body : e;
            }
            for (wi = cf(e.firstChild), Ci = t, Ti = !0, Ei = null, Di = !0, n = Oa(t, null, r, n), t.child = n; n;) n.flags = n.flags & -3 | 4096, n = n.sibling;
          }
          else {
            if (Ni(), r === a) {
              t = yc(e, t, n);
              break a;
            }
            Js(e, t, r, n);
          }
          t = t.child;
        }
        return t;
      case 26: return ic(e, t), e === null ? (n = kf(t.type, null, t.pendingProps, null)) ? t.memoizedState = n : Ti || (n = t.type, e = t.pendingProps, r = Bd(pe.current).createElement(n), r[dt] = t, r[ft] = e, Pd(r, n, e), wt(r), t.stateNode = r) : t.memoizedState = kf(t.type, e.memoizedProps, t.pendingProps, e.memoizedState), null;
      case 27: return _e(t), e === null && Ti && (r = t.stateNode = ff(t.type, t.pendingProps, pe.current), Ci = t, Di = !0, a = wi, Zd(t.type) ? (lf = a, wi = cf(r.firstChild)) : wi = a), Js(e, t, t.pendingProps.children, n), ic(e, t), e === null && (t.flags |= 4194304), t.child;
      case 5: return e === null && Ti && ((a = r = wi) && (r = tf(r, t.type, t.pendingProps, Di), r === null ? a = !1 : (t.stateNode = r, Ci = t, wi = cf(r.firstChild), Di = !1, a = !0)), a || ki(t)), _e(t), a = t.type, o = t.pendingProps, s = e === null ? null : e.memoizedProps, r = o.children, Ud(a, o) ? r = null : s !== null && Ud(a, s) && (t.flags |= 32), t.memoizedState !== null && (a = mo(e, t, _o, null, null, n), Qf._currentValue = a), ic(e, t), Js(e, t, r, n), t.child;
      case 6: return e === null && Ti && ((e = n = wi) && (n = nf(n, t.pendingProps, Di), n === null ? e = !1 : (t.stateNode = n, Ci = t, wi = null, e = !0)), e || ki(t)), null;
      case 13: return fc(e, t, n);
      case 4: return he(t, t.stateNode.containerInfo), r = t.pendingProps, e === null ? t.child = Da(t, null, r, n) : Js(e, t, r, n), t.child;
      case 11: return Ys(e, t, t.type, t.pendingProps, n);
      case 7: return Js(e, t, t.pendingProps, n), t.child;
      case 8: return Js(e, t, t.pendingProps.children, n), t.child;
      case 12: return Js(e, t, t.pendingProps.children, n), t.child;
      case 10: return r = t.pendingProps, zi(t, t.type, r.value), Js(e, t, r.children, n), t.child;
      case 9: return a = t.type._context, r = t.pendingProps.children, Gi(t), a = Ki(a), r = r(a), t.flags |= 1, Js(e, t, r, n), t.child;
      case 14: return Xs(e, t, t.type, t.pendingProps, n);
      case 15: return Zs(e, t, t.type, t.pendingProps, n);
      case 19: return vc(e, t, n);
      case 31: return rc(e, t, n);
      case 22: return Qs(e, t, n, t.pendingProps);
      case 24: return Gi(t), r = Ki(Qi), e === null ? (a = ca(), a === null && (a = Ml, o = Y(), a.pooledCache = o, o.refCount++, o !== null && (a.pooledCacheLanes |= n), a = o), t.memoizedState = {
        parent: r,
        cache: a
      }, Aa(t), zi(t, Qi, a)) : ((e.lanes & n) !== 0 && (ja(e, t), La(t, null, null, n), Ia()), a = e.memoizedState, o = t.memoizedState, a.parent === r ? (r = o.cache, zi(t, Qi, r), r !== a.cache && Hi(t, [Qi], n, !0)) : (a = {
        parent: r,
        cache: r
      }, t.memoizedState = a, t.lanes === 0 && (t.memoizedState = t.updateQueue.baseState = a), zi(t, Qi, r))), Js(e, t, t.pendingProps.children, n), t.child;
      case 29: throw t.pendingProps;
    }
    throw Error(i(156, t.tag));
  }
  function Cc(e) {
    e.flags |= 4;
  }
  function wc(e, t, n, r, i) {
    if ((t = (e.mode & 32) != 0) && (t = !1), t) {
      if (e.flags |= 16777216, (i & 335544128) === i) if (e.stateNode.complete) e.flags |= 8192;
      else if (xu()) e.flags |= 8192;
      else throw va = ma, fa;
    } else e.flags &= -16777217;
  }
  function Tc(e, t) {
    if (t.type !== "stylesheet" || t.state.loading & 4) e.flags &= -16777217;
    else if (e.flags |= 16777216, !Wf(t)) if (xu()) e.flags |= 8192;
    else throw va = ma, fa;
  }
  function Ec(e, t) {
    t !== null && (e.flags |= 4), e.flags & 16384 && (t = e.tag === 22 ? 536870912 : $e(), e.lanes |= t, Kl |= t);
  }
  function Dc(e, t) {
    if (!Ti) switch (e.tailMode) {
      case "hidden":
        t = e.tail;
        for (var n = null; t !== null;) t.alternate !== null && (n = t), t = t.sibling;
        n === null ? e.tail = null : n.sibling = null;
        break;
      case "collapsed":
        n = e.tail;
        for (var r = null; n !== null;) n.alternate !== null && (r = n), n = n.sibling;
        r === null ? t || e.tail === null ? e.tail = null : e.tail.sibling = null : r.sibling = null;
    }
  }
  function Oc(e) {
    var t = e.alternate !== null && e.alternate.child === e.child, n = 0, r = 0;
    if (t) for (var i = e.child; i !== null;) n |= i.lanes | i.childLanes, r |= i.subtreeFlags & 65011712, r |= i.flags & 65011712, i.return = e, i = i.sibling;
    else for (i = e.child; i !== null;) n |= i.lanes | i.childLanes, r |= i.subtreeFlags, r |= i.flags, i.return = e, i = i.sibling;
    return e.subtreeFlags |= r, e.childLanes = n, t;
  }
  function kc(e, t, n) {
    var r = t.pendingProps;
    switch (xi(t), t.tag) {
      case 16:
      case 15:
      case 0:
      case 11:
      case 7:
      case 8:
      case 12:
      case 9:
      case 14: return Oc(t), null;
      case 1: return Oc(t), null;
      case 3: return n = t.stateNode, r = null, e !== null && (r = e.memoizedState.cache), t.memoizedState.cache !== r && (t.flags |= 2048), Bi(Qi), ge(), n.pendingContext && (n.context = n.pendingContext, n.pendingContext = null), (e === null || e.child === null) && (Mi(t) ? Cc(t) : e === null || e.memoizedState.isDehydrated && !(t.flags & 256) || (t.flags |= 1024, Pi())), Oc(t), null;
      case 26:
        var a = t.type, o = t.memoizedState;
        return e === null ? (Cc(t), o === null ? (Oc(t), wc(t, a, null, r, n)) : (Oc(t), Tc(t, o))) : o ? o === e.memoizedState ? (Oc(t), t.flags &= -16777217) : (Cc(t), Oc(t), Tc(t, o)) : (e = e.memoizedProps, e !== r && Cc(t), Oc(t), wc(t, a, e, r, n)), null;
      case 27:
        if (ve(t), n = pe.current, a = t.type, e !== null && t.stateNode != null) e.memoizedProps !== r && Cc(t);
        else {
          if (!r) {
            if (t.stateNode === null) throw Error(i(166));
            return Oc(t), null;
          }
          e = de.current, Mi(t) ? Ai(t, e) : (e = ff(a, r, n), t.stateNode = e, Cc(t));
        }
        return Oc(t), null;
      case 5:
        if (ve(t), a = t.type, e !== null && t.stateNode != null) e.memoizedProps !== r && Cc(t);
        else {
          if (!r) {
            if (t.stateNode === null) throw Error(i(166));
            return Oc(t), null;
          }
          if (o = de.current, Mi(t)) Ai(t, o);
          else {
            var s = Bd(pe.current);
            switch (o) {
              case 1:
                o = s.createElementNS("http://www.w3.org/2000/svg", a);
                break;
              case 2:
                o = s.createElementNS("http://www.w3.org/1998/Math/MathML", a);
                break;
              default: switch (a) {
                case "svg":
                  o = s.createElementNS("http://www.w3.org/2000/svg", a);
                  break;
                case "math":
                  o = s.createElementNS("http://www.w3.org/1998/Math/MathML", a);
                  break;
                case "script":
                  o = s.createElement("div"), o.innerHTML = "<script><\/script>", o = o.removeChild(o.firstChild);
                  break;
                case "select":
                  o = typeof r.is == "string" ? s.createElement("select", { is: r.is }) : s.createElement("select"), r.multiple ? o.multiple = !0 : r.size && (o.size = r.size);
                  break;
                default: o = typeof r.is == "string" ? s.createElement(a, { is: r.is }) : s.createElement(a);
              }
            }
            o[dt] = t, o[ft] = r;
            a: for (s = t.child; s !== null;) {
              if (s.tag === 5 || s.tag === 6) o.appendChild(s.stateNode);
              else if (s.tag !== 4 && s.tag !== 27 && s.child !== null) {
                s.child.return = s, s = s.child;
                continue;
              }
              if (s === t) break a;
              for (; s.sibling === null;) {
                if (s.return === null || s.return === t) break a;
                s = s.return;
              }
              s.sibling.return = s.return, s = s.sibling;
            }
            t.stateNode = o;
            a: switch (Pd(o, a, r), a) {
              case "button":
              case "input":
              case "select":
              case "textarea":
                r = !!r.autoFocus;
                break a;
              case "img":
                r = !0;
                break a;
              default: r = !1;
            }
            r && Cc(t);
          }
        }
        return Oc(t), wc(t, t.type, e === null ? null : e.memoizedProps, t.pendingProps, n), null;
      case 6:
        if (e && t.stateNode != null) e.memoizedProps !== r && Cc(t);
        else {
          if (typeof r != "string" && t.stateNode === null) throw Error(i(166));
          if (e = pe.current, Mi(t)) {
            if (e = t.stateNode, n = t.memoizedProps, r = null, a = Ci, a !== null) switch (a.tag) {
              case 27:
              case 5: r = a.memoizedProps;
            }
            e[dt] = t, e = !!(e.nodeValue === n || r !== null && !0 === r.suppressHydrationWarning || jd(e.nodeValue, n)), e || ki(t, !0);
          } else e = Bd(e).createTextNode(r), e[dt] = t, t.stateNode = e;
        }
        return Oc(t), null;
      case 31:
        if (n = t.memoizedState, e === null || e.memoizedState !== null) {
          if (r = Mi(t), n !== null) {
            if (e === null) {
              if (!r) throw Error(i(318));
              if (e = t.memoizedState, e = e === null ? null : e.dehydrated, !e) throw Error(i(557));
              e[dt] = t;
            } else Ni(), !(t.flags & 128) && (t.memoizedState = null), t.flags |= 4;
            Oc(t), e = !1;
          } else n = Pi(), e !== null && e.memoizedState !== null && (e.memoizedState.hydrationErrors = n), e = !0;
          if (!e) return t.flags & 256 ? (Za(t), t) : (Za(t), null);
          if (t.flags & 128) throw Error(i(558));
        }
        return Oc(t), null;
      case 13:
        if (r = t.memoizedState, e === null || e.memoizedState !== null && e.memoizedState.dehydrated !== null) {
          if (a = Mi(t), r !== null && r.dehydrated !== null) {
            if (e === null) {
              if (!a) throw Error(i(318));
              if (a = t.memoizedState, a = a === null ? null : a.dehydrated, !a) throw Error(i(317));
              a[dt] = t;
            } else Ni(), !(t.flags & 128) && (t.memoizedState = null), t.flags |= 4;
            Oc(t), a = !1;
          } else a = Pi(), e !== null && e.memoizedState !== null && (e.memoizedState.hydrationErrors = a), a = !0;
          if (!a) return t.flags & 256 ? (Za(t), t) : (Za(t), null);
        }
        return Za(t), t.flags & 128 ? (t.lanes = n, t) : (n = r !== null, e = e !== null && e.memoizedState !== null, n && (r = t.child, a = null, r.alternate !== null && r.alternate.memoizedState !== null && r.alternate.memoizedState.cachePool !== null && (a = r.alternate.memoizedState.cachePool.pool), o = null, r.memoizedState !== null && r.memoizedState.cachePool !== null && (o = r.memoizedState.cachePool.pool), o !== a && (r.flags |= 2048)), n !== e && n && (t.child.flags |= 8192), Ec(t, t.updateQueue), Oc(t), null);
      case 4: return ge(), e === null && xd(t.stateNode.containerInfo), Oc(t), null;
      case 10: return Bi(t.type), Oc(t), null;
      case 19:
        if (ue(Qa), r = t.memoizedState, r === null) return Oc(t), null;
        if (a = (t.flags & 128) != 0, o = r.rendering, o === null) if (a) Dc(r, !1);
        else {
          if (Vl !== 0 || e !== null && e.flags & 128) for (e = t.child; e !== null;) {
            if (o = $a(e), o !== null) {
              for (t.flags |= 128, Dc(r, !1), e = o.updateQueue, t.updateQueue = e, Ec(t, e), t.subtreeFlags = 0, e = n, n = t.child; n !== null;) ti(n, e), n = n.sibling;
              return M(Qa, Qa.current & 1 | 2), Ti && vi(t, r.treeForkCount), t.child;
            }
            e = e.sibling;
          }
          r.tail !== null && Ae() > Ql && (t.flags |= 128, a = !0, Dc(r, !1), t.lanes = 4194304);
        }
        else {
          if (!a) if (e = $a(o), e !== null) {
            if (t.flags |= 128, a = !0, e = e.updateQueue, t.updateQueue = e, Ec(t, e), Dc(r, !0), r.tail === null && r.tailMode === "hidden" && !o.alternate && !Ti) return Oc(t), null;
          } else 2 * Ae() - r.renderingStartTime > Ql && n !== 536870912 && (t.flags |= 128, a = !0, Dc(r, !1), t.lanes = 4194304);
          r.isBackwards ? (o.sibling = t.child, t.child = o) : (e = r.last, e === null ? t.child = o : e.sibling = o, r.last = o);
        }
        return r.tail === null ? (Oc(t), null) : (e = r.tail, r.rendering = e, r.tail = e.sibling, r.renderingStartTime = Ae(), e.sibling = null, n = Qa.current, M(Qa, a ? n & 1 | 2 : n & 1), Ti && vi(t, r.treeForkCount), e);
      case 22:
      case 23: return Za(t), Wa(), r = t.memoizedState !== null, e === null ? r && (t.flags |= 8192) : e.memoizedState !== null !== r && (t.flags |= 8192), r ? n & 536870912 && !(t.flags & 128) && (Oc(t), t.subtreeFlags & 6 && (t.flags |= 8192)) : Oc(t), n = t.updateQueue, n !== null && Ec(t, n.retryQueue), n = null, e !== null && e.memoizedState !== null && e.memoizedState.cachePool !== null && (n = e.memoizedState.cachePool.pool), r = null, t.memoizedState !== null && t.memoizedState.cachePool !== null && (r = t.memoizedState.cachePool.pool), r !== n && (t.flags |= 2048), e !== null && ue(sa), null;
      case 24: return n = null, e !== null && (n = e.memoizedState.cache), t.memoizedState.cache !== n && (t.flags |= 2048), Bi(Qi), Oc(t), null;
      case 25: return null;
      case 30: return null;
    }
    throw Error(i(156, t.tag));
  }
  function Ac(e, t) {
    switch (xi(t), t.tag) {
      case 1: return e = t.flags, e & 65536 ? (t.flags = e & -65537 | 128, t) : null;
      case 3: return Bi(Qi), ge(), e = t.flags, e & 65536 && !(e & 128) ? (t.flags = e & -65537 | 128, t) : null;
      case 26:
      case 27:
      case 5: return ve(t), null;
      case 31:
        if (t.memoizedState !== null) {
          if (Za(t), t.alternate === null) throw Error(i(340));
          Ni();
        }
        return e = t.flags, e & 65536 ? (t.flags = e & -65537 | 128, t) : null;
      case 13:
        if (Za(t), e = t.memoizedState, e !== null && e.dehydrated !== null) {
          if (t.alternate === null) throw Error(i(340));
          Ni();
        }
        return e = t.flags, e & 65536 ? (t.flags = e & -65537 | 128, t) : null;
      case 19: return ue(Qa), null;
      case 4: return ge(), null;
      case 10: return Bi(t.type), null;
      case 22:
      case 23: return Za(t), Wa(), e !== null && ue(sa), e = t.flags, e & 65536 ? (t.flags = e & -65537 | 128, t) : null;
      case 24: return Bi(Qi), null;
      case 25: return null;
      default: return null;
    }
  }
  function jc(e, t) {
    switch (xi(t), t.tag) {
      case 3:
        Bi(Qi), ge();
        break;
      case 26:
      case 27:
      case 5:
        ve(t);
        break;
      case 4:
        ge();
        break;
      case 31:
        t.memoizedState !== null && Za(t);
        break;
      case 13:
        Za(t);
        break;
      case 19:
        ue(Qa);
        break;
      case 10:
        Bi(t.type);
        break;
      case 22:
      case 23:
        Za(t), Wa(), e !== null && ue(sa);
        break;
      case 24: Bi(Qi);
    }
  }
  function Mc(e, t) {
    try {
      var n = t.updateQueue, r = n === null ? null : n.lastEffect;
      if (r !== null) {
        var i = r.next;
        n = i;
        do {
          if ((n.tag & e) === e) {
            r = void 0;
            var a = n.create, o = n.inst;
            r = a(), o.destroy = r;
          }
          n = n.next;
        } while (n !== i);
      }
    } catch (e) {
      Hu(t, t.return, e);
    }
  }
  function Nc(e, t, n) {
    try {
      var r = t.updateQueue, i = r === null ? null : r.lastEffect;
      if (i !== null) {
        var a = i.next;
        r = a;
        do {
          if ((r.tag & e) === e) {
            var o = r.inst, s = o.destroy;
            if (s !== void 0) {
              o.destroy = void 0, i = t;
              var c = n, l = s;
              try {
                l();
              } catch (e) {
                Hu(i, c, e);
              }
            }
          }
          r = r.next;
        } while (r !== a);
      }
    } catch (e) {
      Hu(t, t.return, e);
    }
  }
  function Pc(e) {
    var t = e.updateQueue;
    if (t !== null) {
      var n = e.stateNode;
      try {
        za(t, n);
      } catch (t) {
        Hu(e, e.return, t);
      }
    }
  }
  function Fc(e, t, n) {
    n.props = Is(e.type, e.memoizedProps), n.state = e.memoizedState;
    try {
      n.componentWillUnmount();
    } catch (n) {
      Hu(e, t, n);
    }
  }
  function Ic(e, t) {
    try {
      var n = e.ref;
      if (n !== null) {
        switch (e.tag) {
          case 26:
          case 27:
          case 5:
            var r = e.stateNode;
            break;
          case 30:
            r = e.stateNode;
            break;
          default: r = e.stateNode;
        }
        typeof n == "function" ? e.refCleanup = n(r) : n.current = r;
      }
    } catch (n) {
      Hu(e, t, n);
    }
  }
  function Lc(e, t) {
    var n = e.ref, r = e.refCleanup;
    if (n !== null) if (typeof r == "function") try {
      r();
    } catch (n) {
      Hu(e, t, n);
    } finally {
      e.refCleanup = null, e = e.alternate, e != null && (e.refCleanup = null);
    }
    else if (typeof n == "function") try {
      n(null);
    } catch (n) {
      Hu(e, t, n);
    }
    else n.current = null;
  }
  function Rc(e) {
    var t = e.type, n = e.memoizedProps, r = e.stateNode;
    try {
      a: switch (t) {
        case "button":
        case "input":
        case "select":
        case "textarea":
          n.autoFocus && r.focus();
          break a;
        case "img": n.src ? r.src = n.src : n.srcSet && (r.srcset = n.srcSet);
      }
    } catch (t) {
      Hu(e, e.return, t);
    }
  }
  function zc(e, t, n) {
    try {
      var r = e.stateNode;
      Fd(r, e.type, n, t), r[ft] = t;
    } catch (t) {
      Hu(e, e.return, t);
    }
  }
  function Bc(e) {
    return e.tag === 5 || e.tag === 3 || e.tag === 26 || e.tag === 27 && Zd(e.type) || e.tag === 4;
  }
  function Vc(e) {
    a: for (;;) {
      for (; e.sibling === null;) {
        if (e.return === null || Bc(e.return)) return null;
        e = e.return;
      }
      for (e.sibling.return = e.return, e = e.sibling; e.tag !== 5 && e.tag !== 6 && e.tag !== 18;) {
        if (e.tag === 27 && Zd(e.type) || e.flags & 2 || e.child === null || e.tag === 4) continue a;
        e.child.return = e, e = e.child;
      }
      if (!(e.flags & 2)) return e.stateNode;
    }
  }
  function Hc(e, t, n) {
    var r = e.tag;
    if (r === 5 || r === 6) e = e.stateNode, t ? (n.nodeType === 9 ? n.body : n.nodeName === "HTML" ? n.ownerDocument.body : n).insertBefore(e, t) : (t = n.nodeType === 9 ? n.body : n.nodeName === "HTML" ? n.ownerDocument.body : n, t.appendChild(e), n = n._reactRootContainer, n != null || t.onclick !== null || (t.onclick = nn));
    else if (r !== 4 && (r === 27 && Zd(e.type) && (n = e.stateNode, t = null), e = e.child, e !== null)) for (Hc(e, t, n), e = e.sibling; e !== null;) Hc(e, t, n), e = e.sibling;
  }
  function Uc(e, t, n) {
    var r = e.tag;
    if (r === 5 || r === 6) e = e.stateNode, t ? n.insertBefore(e, t) : n.appendChild(e);
    else if (r !== 4 && (r === 27 && Zd(e.type) && (n = e.stateNode), e = e.child, e !== null)) for (Uc(e, t, n), e = e.sibling; e !== null;) Uc(e, t, n), e = e.sibling;
  }
  function Wc(e) {
    var t = e.stateNode, n = e.memoizedProps;
    try {
      for (var r = e.type, i = t.attributes; i.length;) t.removeAttributeNode(i[0]);
      Pd(t, r, n), t[dt] = e, t[ft] = n;
    } catch (t) {
      Hu(e, e.return, t);
    }
  }
  var Gc = !1, Kc = !1, qc = !1, Jc = typeof WeakSet == "function" ? WeakSet : Set, Yc = null;
  function Xc(e, t) {
    if (e = e.containerInfo, Rd = sp, e = yr(e), br(e)) {
      if ("selectionStart" in e) var n = {
        start: e.selectionStart,
        end: e.selectionEnd
      };
      else a: {
        n = (n = e.ownerDocument) && n.defaultView || window;
        var r = n.getSelection && n.getSelection();
        if (r && r.rangeCount !== 0) {
          n = r.anchorNode;
          var a = r.anchorOffset, o = r.focusNode;
          r = r.focusOffset;
          try {
            n.nodeType, o.nodeType;
          } catch {
            n = null;
            break a;
          }
          var s = 0, c = -1, l = -1, u = 0, d = 0, f = e, p = null;
          b: for (;;) {
            for (var m; f !== n || a !== 0 && f.nodeType !== 3 || (c = s + a), f !== o || r !== 0 && f.nodeType !== 3 || (l = s + r), f.nodeType === 3 && (s += f.nodeValue.length), (m = f.firstChild) !== null;) p = f, f = m;
            for (;;) {
              if (f === e) break b;
              if (p === n && ++u === a && (c = s), p === o && ++d === r && (l = s), (m = f.nextSibling) !== null) break;
              f = p, p = f.parentNode;
            }
            f = m;
          }
          n = c === -1 || l === -1 ? null : {
            start: c,
            end: l
          };
        } else n = null;
      }
      n ||= {
        start: 0,
        end: 0
      };
    } else n = null;
    for (zd = {
      focusedElem: e,
      selectionRange: n
    }, sp = !1, Yc = t; Yc !== null;) if (t = Yc, e = t.child, t.subtreeFlags & 1028 && e !== null) e.return = t, Yc = e;
    else for (; Yc !== null;) {
      switch (t = Yc, o = t.alternate, e = t.flags, t.tag) {
        case 0:
          if (e & 4 && (e = t.updateQueue, e = e === null ? null : e.events, e !== null)) for (n = 0; n < e.length; n++) a = e[n], a.ref.impl = a.nextImpl;
          break;
        case 11:
        case 15: break;
        case 1:
          if (e & 1024 && o !== null) {
            e = void 0, n = t, a = o.memoizedProps, o = o.memoizedState, r = n.stateNode;
            try {
              var h = Is(n.type, a);
              e = r.getSnapshotBeforeUpdate(h, o), r.__reactInternalSnapshotBeforeUpdate = e;
            } catch (e) {
              Hu(n, n.return, e);
            }
          }
          break;
        case 3:
          if (e & 1024) {
            if (e = t.stateNode.containerInfo, n = e.nodeType, n === 9) ef(e);
            else if (n === 1) switch (e.nodeName) {
              case "HEAD":
              case "HTML":
              case "BODY":
                ef(e);
                break;
              default: e.textContent = "";
            }
          }
          break;
        case 5:
        case 26:
        case 27:
        case 6:
        case 4:
        case 17: break;
        default: if (e & 1024) throw Error(i(163));
      }
      if (e = t.sibling, e !== null) {
        e.return = t.return, Yc = e;
        break;
      }
      Yc = t.return;
    }
  }
  function Zc(e, t, n) {
    var r = n.flags;
    switch (n.tag) {
      case 0:
      case 11:
      case 15:
        fl(e, n), r & 4 && Mc(5, n);
        break;
      case 1:
        if (fl(e, n), r & 4) if (e = n.stateNode, t === null) try {
          e.componentDidMount();
        } catch (e) {
          Hu(n, n.return, e);
        }
        else {
          var i = Is(n.type, t.memoizedProps);
          t = t.memoizedState;
          try {
            e.componentDidUpdate(i, t, e.__reactInternalSnapshotBeforeUpdate);
          } catch (e) {
            Hu(n, n.return, e);
          }
        }
        r & 64 && Pc(n), r & 512 && Ic(n, n.return);
        break;
      case 3:
        if (fl(e, n), r & 64 && (e = n.updateQueue, e !== null)) {
          if (t = null, n.child !== null) switch (n.child.tag) {
            case 27:
            case 5:
              t = n.child.stateNode;
              break;
            case 1: t = n.child.stateNode;
          }
          try {
            za(e, t);
          } catch (e) {
            Hu(n, n.return, e);
          }
        }
        break;
      case 27: t === null && r & 4 && Wc(n);
      case 26:
      case 5:
        fl(e, n), t === null && r & 4 && Rc(n), r & 512 && Ic(n, n.return);
        break;
      case 12:
        fl(e, n);
        break;
      case 31:
        fl(e, n), r & 4 && rl(e, n);
        break;
      case 13:
        fl(e, n), r & 4 && il(e, n), r & 64 && (e = n.memoizedState, e !== null && (e = e.dehydrated, e !== null && (n = Ku.bind(null, n), sf(e, n))));
        break;
      case 22:
        if (r = n.memoizedState !== null || Gc, !r) {
          t = t !== null && t.memoizedState !== null || Kc, i = Gc;
          var a = Kc;
          Gc = r, (Kc = t) && !a ? ml(e, n, (n.subtreeFlags & 8772) != 0) : fl(e, n), Gc = i, Kc = a;
        }
        break;
      case 30: break;
      default: fl(e, n);
    }
  }
  function Qc(e) {
    var t = e.alternate;
    t !== null && (e.alternate = null, Qc(t)), e.child = null, e.deletions = null, e.sibling = null, e.tag === 5 && (t = e.stateNode, t !== null && yt(t)), e.stateNode = null, e.return = null, e.dependencies = null, e.memoizedProps = null, e.memoizedState = null, e.pendingProps = null, e.stateNode = null, e.updateQueue = null;
  }
  var $c = null, el = !1;
  function tl(e, t, n) {
    for (n = n.child; n !== null;) nl(e, t, n), n = n.sibling;
  }
  function nl(e, t, n) {
    if (Be && typeof Be.onCommitFiberUnmount == "function") try {
      Be.onCommitFiberUnmount(ze, n);
    } catch {}
    switch (n.tag) {
      case 26:
        Kc || Lc(n, t), tl(e, t, n), n.memoizedState ? n.memoizedState.count-- : n.stateNode && (n = n.stateNode, n.parentNode.removeChild(n));
        break;
      case 27:
        Kc || Lc(n, t);
        var r = $c, i = el;
        Zd(n.type) && ($c = n.stateNode, el = !1), tl(e, t, n), pf(n.stateNode), $c = r, el = i;
        break;
      case 5: Kc || Lc(n, t);
      case 6:
        if (r = $c, i = el, $c = null, tl(e, t, n), $c = r, el = i, $c !== null) if (el) try {
          ($c.nodeType === 9 ? $c.body : $c.nodeName === "HTML" ? $c.ownerDocument.body : $c).removeChild(n.stateNode);
        } catch (e) {
          Hu(n, t, e);
        }
        else try {
          $c.removeChild(n.stateNode);
        } catch (e) {
          Hu(n, t, e);
        }
        break;
      case 18:
        $c !== null && (el ? (e = $c, Qd(e.nodeType === 9 ? e.body : e.nodeName === "HTML" ? e.ownerDocument.body : e, n.stateNode), Np(e)) : Qd($c, n.stateNode));
        break;
      case 4:
        r = $c, i = el, $c = n.stateNode.containerInfo, el = !0, tl(e, t, n), $c = r, el = i;
        break;
      case 0:
      case 11:
      case 14:
      case 15:
        Nc(2, n, t), Kc || Nc(4, n, t), tl(e, t, n);
        break;
      case 1:
        Kc || (Lc(n, t), r = n.stateNode, typeof r.componentWillUnmount == "function" && Fc(n, t, r)), tl(e, t, n);
        break;
      case 21:
        tl(e, t, n);
        break;
      case 22:
        Kc = (r = Kc) || n.memoizedState !== null, tl(e, t, n), Kc = r;
        break;
      default: tl(e, t, n);
    }
  }
  function rl(e, t) {
    if (t.memoizedState === null && (e = t.alternate, e !== null && (e = e.memoizedState, e !== null))) {
      e = e.dehydrated;
      try {
        Np(e);
      } catch (e) {
        Hu(t, t.return, e);
      }
    }
  }
  function il(e, t) {
    if (t.memoizedState === null && (e = t.alternate, e !== null && (e = e.memoizedState, e !== null && (e = e.dehydrated, e !== null)))) try {
      Np(e);
    } catch (e) {
      Hu(t, t.return, e);
    }
  }
  function al(e) {
    switch (e.tag) {
      case 31:
      case 13:
      case 19:
        var t = e.stateNode;
        return t === null && (t = e.stateNode = new Jc()), t;
      case 22: return e = e.stateNode, t = e._retryCache, t === null && (t = e._retryCache = new Jc()), t;
      default: throw Error(i(435, e.tag));
    }
  }
  function ol(e, t) {
    var n = al(e);
    t.forEach(function(t) {
      if (!n.has(t)) {
        n.add(t);
        var r = qu.bind(null, e, t);
        t.then(r, r);
      }
    });
  }
  function sl(e, t) {
    var n = t.deletions;
    if (n !== null) for (var r = 0; r < n.length; r++) {
      var a = n[r], o = e, s = t, c = s;
      a: for (; c !== null;) {
        switch (c.tag) {
          case 27:
            if (Zd(c.type)) {
              $c = c.stateNode, el = !1;
              break a;
            }
            break;
          case 5:
            $c = c.stateNode, el = !1;
            break a;
          case 3:
          case 4:
            $c = c.stateNode.containerInfo, el = !0;
            break a;
        }
        c = c.return;
      }
      if ($c === null) throw Error(i(160));
      nl(o, s, a), $c = null, el = !1, o = a.alternate, o !== null && (o.return = null), a.return = null;
    }
    if (t.subtreeFlags & 13886) for (t = t.child; t !== null;) ll(t, e), t = t.sibling;
  }
  var cl = null;
  function ll(e, t) {
    var n = e.alternate, r = e.flags;
    switch (e.tag) {
      case 0:
      case 11:
      case 14:
      case 15:
        sl(t, e), ul(e), r & 4 && (Nc(3, e, e.return), Mc(3, e), Nc(5, e, e.return));
        break;
      case 1:
        sl(t, e), ul(e), r & 512 && (Kc || n === null || Lc(n, n.return)), r & 64 && Gc && (e = e.updateQueue, e !== null && (r = e.callbacks, r !== null && (n = e.shared.hiddenCallbacks, e.shared.hiddenCallbacks = n === null ? r : n.concat(r))));
        break;
      case 26:
        var a = cl;
        if (sl(t, e), ul(e), r & 512 && (Kc || n === null || Lc(n, n.return)), r & 4) {
          var o = n === null ? null : n.memoizedState;
          if (r = e.memoizedState, n === null) if (r === null) if (e.stateNode === null) {
            a: {
              r = e.type, n = e.memoizedProps, a = a.ownerDocument || a;
              b: switch (r) {
                case "title":
                  o = a.getElementsByTagName("title")[0], (!o || o[vt] || o[dt] || o.namespaceURI === "http://www.w3.org/2000/svg" || o.hasAttribute("itemprop")) && (o = a.createElement(r), a.head.insertBefore(o, a.querySelector("head > title"))), Pd(o, r, n), o[dt] = e, wt(o), r = o;
                  break a;
                case "link":
                  var s = Vf("link", "href", a).get(r + (n.href || ""));
                  if (s) {
                    for (var c = 0; c < s.length; c++) if (o = s[c], o.getAttribute("href") === (n.href == null || n.href === "" ? null : n.href) && o.getAttribute("rel") === (n.rel == null ? null : n.rel) && o.getAttribute("title") === (n.title == null ? null : n.title) && o.getAttribute("crossorigin") === (n.crossOrigin == null ? null : n.crossOrigin)) {
                      s.splice(c, 1);
                      break b;
                    }
                  }
                  o = a.createElement(r), Pd(o, r, n), a.head.appendChild(o);
                  break;
                case "meta":
                  if (s = Vf("meta", "content", a).get(r + (n.content || ""))) {
                    for (c = 0; c < s.length; c++) if (o = s[c], o.getAttribute("content") === (n.content == null ? null : "" + n.content) && o.getAttribute("name") === (n.name == null ? null : n.name) && o.getAttribute("property") === (n.property == null ? null : n.property) && o.getAttribute("http-equiv") === (n.httpEquiv == null ? null : n.httpEquiv) && o.getAttribute("charset") === (n.charSet == null ? null : n.charSet)) {
                      s.splice(c, 1);
                      break b;
                    }
                  }
                  o = a.createElement(r), Pd(o, r, n), a.head.appendChild(o);
                  break;
                default: throw Error(i(468, r));
              }
              o[dt] = e, wt(o), r = o;
            }
            e.stateNode = r;
          } else Hf(a, e.type, e.stateNode);
          else e.stateNode = If(a, r, e.memoizedProps);
          else o === r ? r === null && e.stateNode !== null && zc(e, e.memoizedProps, n.memoizedProps) : (o === null ? n.stateNode !== null && (n = n.stateNode, n.parentNode.removeChild(n)) : o.count--, r === null ? Hf(a, e.type, e.stateNode) : If(a, r, e.memoizedProps));
        }
        break;
      case 27:
        sl(t, e), ul(e), r & 512 && (Kc || n === null || Lc(n, n.return)), n !== null && r & 4 && zc(e, e.memoizedProps, n.memoizedProps);
        break;
      case 5:
        if (sl(t, e), ul(e), r & 512 && (Kc || n === null || Lc(n, n.return)), e.flags & 32) {
          a = e.stateNode;
          try {
            Jt(a, "");
          } catch (t) {
            Hu(e, e.return, t);
          }
        }
        r & 4 && e.stateNode != null && (a = e.memoizedProps, zc(e, a, n === null ? a : n.memoizedProps)), r & 1024 && (qc = !0);
        break;
      case 6:
        if (sl(t, e), ul(e), r & 4) {
          if (e.stateNode === null) throw Error(i(162));
          r = e.memoizedProps, n = e.stateNode;
          try {
            n.nodeValue = r;
          } catch (t) {
            Hu(e, e.return, t);
          }
        }
        break;
      case 3:
        if (Bf = null, a = cl, cl = gf(t.containerInfo), sl(t, e), cl = a, ul(e), r & 4 && n !== null && n.memoizedState.isDehydrated) try {
          Np(t.containerInfo);
        } catch (t) {
          Hu(e, e.return, t);
        }
        qc && (qc = !1, dl(e));
        break;
      case 4:
        r = cl, cl = gf(e.stateNode.containerInfo), sl(t, e), ul(e), cl = r;
        break;
      case 12:
        sl(t, e), ul(e);
        break;
      case 31:
        sl(t, e), ul(e), r & 4 && (r = e.updateQueue, r !== null && (e.updateQueue = null, ol(e, r)));
        break;
      case 13:
        sl(t, e), ul(e), e.child.flags & 8192 && e.memoizedState !== null != (n !== null && n.memoizedState !== null) && (Xl = Ae()), r & 4 && (r = e.updateQueue, r !== null && (e.updateQueue = null, ol(e, r)));
        break;
      case 22:
        a = e.memoizedState !== null;
        var l = n !== null && n.memoizedState !== null, u = Gc, d = Kc;
        if (Gc = u || a, Kc = d || l, sl(t, e), Kc = d, Gc = u, ul(e), r & 8192) a: for (t = e.stateNode, t._visibility = a ? t._visibility & -2 : t._visibility | 1, a && (n === null || l || Gc || Kc || pl(e)), n = null, t = e;;) {
          if (t.tag === 5 || t.tag === 26) {
            if (n === null) {
              l = n = t;
              try {
                if (o = l.stateNode, a) s = o.style, typeof s.setProperty == "function" ? s.setProperty("display", "none", "important") : s.display = "none";
                else {
                  c = l.stateNode;
                  var f = l.memoizedProps.style, p = f != null && f.hasOwnProperty("display") ? f.display : null;
                  c.style.display = p == null || typeof p == "boolean" ? "" : ("" + p).trim();
                }
              } catch (e) {
                Hu(l, l.return, e);
              }
            }
          } else if (t.tag === 6) {
            if (n === null) {
              l = t;
              try {
                l.stateNode.nodeValue = a ? "" : l.memoizedProps;
              } catch (e) {
                Hu(l, l.return, e);
              }
            }
          } else if (t.tag === 18) {
            if (n === null) {
              l = t;
              try {
                var m = l.stateNode;
                a ? $d(m, !0) : $d(l.stateNode, !1);
              } catch (e) {
                Hu(l, l.return, e);
              }
            }
          } else if ((t.tag !== 22 && t.tag !== 23 || t.memoizedState === null || t === e) && t.child !== null) {
            t.child.return = t, t = t.child;
            continue;
          }
          if (t === e) break a;
          for (; t.sibling === null;) {
            if (t.return === null || t.return === e) break a;
            n === t && (n = null), t = t.return;
          }
          n === t && (n = null), t.sibling.return = t.return, t = t.sibling;
        }
        r & 4 && (r = e.updateQueue, r !== null && (n = r.retryQueue, n !== null && (r.retryQueue = null, ol(e, n))));
        break;
      case 19:
        sl(t, e), ul(e), r & 4 && (r = e.updateQueue, r !== null && (e.updateQueue = null, ol(e, r)));
        break;
      case 30: break;
      case 21: break;
      default: sl(t, e), ul(e);
    }
  }
  function ul(e) {
    var t = e.flags;
    if (t & 2) {
      try {
        for (var n, r = e.return; r !== null;) {
          if (Bc(r)) {
            n = r;
            break;
          }
          r = r.return;
        }
        if (n == null) throw Error(i(160));
        switch (n.tag) {
          case 27:
            var a = n.stateNode;
            Uc(e, Vc(e), a);
            break;
          case 5:
            var o = n.stateNode;
            n.flags & 32 && (Jt(o, ""), n.flags &= -33), Uc(e, Vc(e), o);
            break;
          case 3:
          case 4:
            var s = n.stateNode.containerInfo;
            Hc(e, Vc(e), s);
            break;
          default: throw Error(i(161));
        }
      } catch (t) {
        Hu(e, e.return, t);
      }
      e.flags &= -3;
    }
    t & 4096 && (e.flags &= -4097);
  }
  function dl(e) {
    if (e.subtreeFlags & 1024) for (e = e.child; e !== null;) {
      var t = e;
      dl(t), t.tag === 5 && t.flags & 1024 && t.stateNode.reset(), e = e.sibling;
    }
  }
  function fl(e, t) {
    if (t.subtreeFlags & 8772) for (t = t.child; t !== null;) Zc(e, t.alternate, t), t = t.sibling;
  }
  function pl(e) {
    for (e = e.child; e !== null;) {
      var t = e;
      switch (t.tag) {
        case 0:
        case 11:
        case 14:
        case 15:
          Nc(4, t, t.return), pl(t);
          break;
        case 1:
          Lc(t, t.return);
          var n = t.stateNode;
          typeof n.componentWillUnmount == "function" && Fc(t, t.return, n), pl(t);
          break;
        case 27: pf(t.stateNode);
        case 26:
        case 5:
          Lc(t, t.return), pl(t);
          break;
        case 22:
          t.memoizedState === null && pl(t);
          break;
        case 30:
          pl(t);
          break;
        default: pl(t);
      }
      e = e.sibling;
    }
  }
  function ml(e, t, n) {
    for (n &&= (t.subtreeFlags & 8772) != 0, t = t.child; t !== null;) {
      var r = t.alternate, i = e, a = t, o = a.flags;
      switch (a.tag) {
        case 0:
        case 11:
        case 15:
          ml(i, a, n), Mc(4, a);
          break;
        case 1:
          if (ml(i, a, n), r = a, i = r.stateNode, typeof i.componentDidMount == "function") try {
            i.componentDidMount();
          } catch (e) {
            Hu(r, r.return, e);
          }
          if (r = a, i = r.updateQueue, i !== null) {
            var s = r.stateNode;
            try {
              var c = i.shared.hiddenCallbacks;
              if (c !== null) for (i.shared.hiddenCallbacks = null, i = 0; i < c.length; i++) Ra(c[i], s);
            } catch (e) {
              Hu(r, r.return, e);
            }
          }
          n && o & 64 && Pc(a), Ic(a, a.return);
          break;
        case 27: Wc(a);
        case 26:
        case 5:
          ml(i, a, n), n && r === null && o & 4 && Rc(a), Ic(a, a.return);
          break;
        case 12:
          ml(i, a, n);
          break;
        case 31:
          ml(i, a, n), n && o & 4 && rl(i, a);
          break;
        case 13:
          ml(i, a, n), n && o & 4 && il(i, a);
          break;
        case 22:
          a.memoizedState === null && ml(i, a, n), Ic(a, a.return);
          break;
        case 30: break;
        default: ml(i, a, n);
      }
      t = t.sibling;
    }
  }
  function hl(e, t) {
    var n = null;
    e !== null && e.memoizedState !== null && e.memoizedState.cachePool !== null && (n = e.memoizedState.cachePool.pool), e = null, t.memoizedState !== null && t.memoizedState.cachePool !== null && (e = t.memoizedState.cachePool.pool), e !== n && (e != null && e.refCount++, n != null && $i(n));
  }
  function gl(e, t) {
    e = null, t.alternate !== null && (e = t.alternate.memoizedState.cache), t = t.memoizedState.cache, t !== e && (t.refCount++, e != null && $i(e));
  }
  function _l(e, t, n, r) {
    if (t.subtreeFlags & 10256) for (t = t.child; t !== null;) vl(e, t, n, r), t = t.sibling;
  }
  function vl(e, t, n, r) {
    var i = t.flags;
    switch (t.tag) {
      case 0:
      case 11:
      case 15:
        _l(e, t, n, r), i & 2048 && Mc(9, t);
        break;
      case 1:
        _l(e, t, n, r);
        break;
      case 3:
        _l(e, t, n, r), i & 2048 && (e = null, t.alternate !== null && (e = t.alternate.memoizedState.cache), t = t.memoizedState.cache, t !== e && (t.refCount++, e != null && $i(e)));
        break;
      case 12:
        if (i & 2048) {
          _l(e, t, n, r), e = t.stateNode;
          try {
            var a = t.memoizedProps, o = a.id, s = a.onPostCommit;
            typeof s == "function" && s(o, t.alternate === null ? "mount" : "update", e.passiveEffectDuration, -0);
          } catch (e) {
            Hu(t, t.return, e);
          }
        } else _l(e, t, n, r);
        break;
      case 31:
        _l(e, t, n, r);
        break;
      case 13:
        _l(e, t, n, r);
        break;
      case 23: break;
      case 22:
        a = t.stateNode, o = t.alternate, t.memoizedState === null ? a._visibility & 2 ? _l(e, t, n, r) : (a._visibility |= 2, yl(e, t, n, r, (t.subtreeFlags & 10256) != 0 || !1)) : a._visibility & 2 ? _l(e, t, n, r) : bl(e, t), i & 2048 && hl(o, t);
        break;
      case 24:
        _l(e, t, n, r), i & 2048 && gl(t.alternate, t);
        break;
      default: _l(e, t, n, r);
    }
  }
  function yl(e, t, n, r, i) {
    for (i &&= (t.subtreeFlags & 10256) != 0 || !1, t = t.child; t !== null;) {
      var a = e, o = t, s = n, c = r, l = o.flags;
      switch (o.tag) {
        case 0:
        case 11:
        case 15:
          yl(a, o, s, c, i), Mc(8, o);
          break;
        case 23: break;
        case 22:
          var u = o.stateNode;
          o.memoizedState === null ? (u._visibility |= 2, yl(a, o, s, c, i)) : u._visibility & 2 ? yl(a, o, s, c, i) : bl(a, o), i && l & 2048 && hl(o.alternate, o);
          break;
        case 24:
          yl(a, o, s, c, i), i && l & 2048 && gl(o.alternate, o);
          break;
        default: yl(a, o, s, c, i);
      }
      t = t.sibling;
    }
  }
  function bl(e, t) {
    if (t.subtreeFlags & 10256) for (t = t.child; t !== null;) {
      var n = e, r = t, i = r.flags;
      switch (r.tag) {
        case 22:
          bl(n, r), i & 2048 && hl(r.alternate, r);
          break;
        case 24:
          bl(n, r), i & 2048 && gl(r.alternate, r);
          break;
        default: bl(n, r);
      }
      t = t.sibling;
    }
  }
  var xl = 8192;
  function Sl(e, t, n) {
    if (e.subtreeFlags & xl) for (e = e.child; e !== null;) Cl(e, t, n), e = e.sibling;
  }
  function Cl(e, t, n) {
    switch (e.tag) {
      case 26:
        Sl(e, t, n), e.flags & xl && e.memoizedState !== null && Gf(n, cl, e.memoizedState, e.memoizedProps);
        break;
      case 5:
        Sl(e, t, n);
        break;
      case 3:
      case 4:
        var r = cl;
        cl = gf(e.stateNode.containerInfo), Sl(e, t, n), cl = r;
        break;
      case 22:
        e.memoizedState === null && (r = e.alternate, r !== null && r.memoizedState !== null ? (r = xl, xl = 16777216, Sl(e, t, n), xl = r) : Sl(e, t, n));
        break;
      default: Sl(e, t, n);
    }
  }
  function wl(e) {
    var t = e.alternate;
    if (t !== null && (e = t.child, e !== null)) {
      t.child = null;
      do
        t = e.sibling, e.sibling = null, e = t;
      while (e !== null);
    }
  }
  function Tl(e) {
    var t = e.deletions;
    if (e.flags & 16) {
      if (t !== null) for (var n = 0; n < t.length; n++) {
        var r = t[n];
        Yc = r, Ol(r, e);
      }
      wl(e);
    }
    if (e.subtreeFlags & 10256) for (e = e.child; e !== null;) El(e), e = e.sibling;
  }
  function El(e) {
    switch (e.tag) {
      case 0:
      case 11:
      case 15:
        Tl(e), e.flags & 2048 && Nc(9, e, e.return);
        break;
      case 3:
        Tl(e);
        break;
      case 12:
        Tl(e);
        break;
      case 22:
        var t = e.stateNode;
        e.memoizedState !== null && t._visibility & 2 && (e.return === null || e.return.tag !== 13) ? (t._visibility &= -3, Dl(e)) : Tl(e);
        break;
      default: Tl(e);
    }
  }
  function Dl(e) {
    var t = e.deletions;
    if (e.flags & 16) {
      if (t !== null) for (var n = 0; n < t.length; n++) {
        var r = t[n];
        Yc = r, Ol(r, e);
      }
      wl(e);
    }
    for (e = e.child; e !== null;) {
      switch (t = e, t.tag) {
        case 0:
        case 11:
        case 15:
          Nc(8, t, t.return), Dl(t);
          break;
        case 22:
          n = t.stateNode, n._visibility & 2 && (n._visibility &= -3, Dl(t));
          break;
        default: Dl(t);
      }
      e = e.sibling;
    }
  }
  function Ol(e, t) {
    for (; Yc !== null;) {
      var n = Yc;
      switch (n.tag) {
        case 0:
        case 11:
        case 15:
          Nc(8, n, t);
          break;
        case 23:
        case 22:
          if (n.memoizedState !== null && n.memoizedState.cachePool !== null) {
            var r = n.memoizedState.cachePool.pool;
            r != null && r.refCount++;
          }
          break;
        case 24: $i(n.memoizedState.cache);
      }
      if (r = n.child, r !== null) r.return = n, Yc = r;
      else a: for (n = e; Yc !== null;) {
        r = Yc;
        var i = r.sibling, a = r.return;
        if (Qc(r), r === n) {
          Yc = null;
          break a;
        }
        if (i !== null) {
          i.return = a, Yc = i;
          break a;
        }
        Yc = a;
      }
    }
  }
  var kl = {
    getCacheForType: function(e) {
      var t = Ki(Qi), n = t.data.get(e);
      return n === void 0 && (n = e(), t.data.set(e, n)), n;
    },
    cacheSignal: function() {
      return Ki(Qi).controller.signal;
    }
  }, Al = typeof WeakMap == "function" ? WeakMap : Map, jl = 0, Ml = null, Nl = null, Pl = 0, Fl = 0, Il = null, Ll = !1, Rl = !1, zl = !1, Bl = 0, Vl = 0, Hl = 0, Ul = 0, Wl = 0, Gl = 0, Kl = 0, ql = null, Jl = null, Yl = !1, Xl = 0, Zl = 0, Ql = Infinity, $l = null, eu = null, tu = 0, nu = null, ru = null, iu = 0, au = 0, ou = null, su = null, cu = 0, lu = null;
  function uu() {
    return jl & 2 && Pl !== 0 ? Pl & -Pl : k.T === null ? ct() : ld();
  }
  function du() {
    if (Gl === 0) if (!(Pl & 536870912) || Ti) {
      var e = qe;
      qe <<= 1, !(qe & 3932160) && (qe = 262144), Gl = e;
    } else Gl = 536870912;
    return e = Ga.current, e !== null && (e.flags |= 32), Gl;
  }
  function fu(e, t, n) {
    (e === Ml && (Fl === 2 || Fl === 9) || e.cancelPendingCommit !== null) && (yu(e, 0), gu(e, Pl, Gl, !1)), tt(e, n), (!(jl & 2) || e !== Ml) && (e === Ml && (!(jl & 2) && (Ul |= n), Vl === 4 && gu(e, Pl, Gl, !1)), td(e));
  }
  function pu(e, t, n) {
    if (jl & 6) throw Error(i(327));
    var r = !n && (t & 127) == 0 && (t & e.expiredLanes) === 0 || Ze(e, t), a = r ? Du(e, t) : Tu(e, t, !0), o = r;
    do {
      if (a === 0) {
        Rl && !r && gu(e, t, 0, !1);
        break;
      } else {
        if (n = e.current.alternate, o && !hu(n)) {
          a = Tu(e, t, !1), o = !1;
          continue;
        }
        if (a === 2) {
          if (o = t, e.errorRecoveryDisabledLanes & o) var s = 0;
          else s = e.pendingLanes & -536870913, s = s === 0 ? s & 536870912 ? 536870912 : 0 : s;
          if (s !== 0) {
            t = s;
            a: {
              var c = e;
              a = ql;
              var l = c.current.memoizedState.isDehydrated;
              if (l && (yu(c, s).flags |= 256), s = Tu(c, s, !1), s !== 2) {
                if (zl && !l) {
                  c.errorRecoveryDisabledLanes |= o, Ul |= o, a = 4;
                  break a;
                }
                o = Jl, Jl = a, o !== null && (Jl === null ? Jl = o : Jl.push.apply(Jl, o));
              }
              a = s;
            }
            if (o = !1, a !== 2) continue;
          }
        }
        if (a === 1) {
          yu(e, 0), gu(e, t, 0, !0);
          break;
        }
        a: {
          switch (r = e, o = a, o) {
            case 0:
            case 1: throw Error(i(345));
            case 4: if ((t & 4194048) !== t) break;
            case 6:
              gu(r, t, Gl, !Ll);
              break a;
            case 2:
              Jl = null;
              break;
            case 3:
            case 5: break;
            default: throw Error(i(329));
          }
          if ((t & 62914560) === t && (a = Xl + 300 - Ae(), 10 < a)) {
            if (gu(r, t, Gl, !Ll), Xe(r, 0, !0) !== 0) break a;
            iu = t, r.timeoutHandle = Kd(mu.bind(null, r, n, Jl, $l, Yl, t, Gl, Ul, Kl, Ll, o, "Throttled", -0, 0), a);
            break a;
          }
          mu(r, n, Jl, $l, Yl, t, Gl, Ul, Kl, Ll, o, null, -0, 0);
        }
      }
      break;
    } while (1);
    td(e);
  }
  function mu(e, t, n, r, i, a, o, s, c, l, u, d, f, p) {
    if (e.timeoutHandle = -1, d = t.subtreeFlags, d & 8192 || (d & 16785408) == 16785408) {
      d = {
        stylesheets: null,
        count: 0,
        imgCount: 0,
        imgBytes: 0,
        suspenseyImages: [],
        waitingForImages: !0,
        waitingForViewTransition: !1,
        unsuspend: nn
      }, Cl(t, a, d);
      var m = (a & 62914560) === a ? Xl - Ae() : (a & 4194048) === a ? Zl - Ae() : 0;
      if (m = qf(d, m), m !== null) {
        iu = a, e.cancelPendingCommit = m(Pu.bind(null, e, t, a, n, r, i, o, s, c, u, d, null, f, p)), gu(e, a, o, !l);
        return;
      }
    }
    Pu(e, t, a, n, r, i, o, s, c);
  }
  function hu(e) {
    for (var t = e;;) {
      var n = t.tag;
      if ((n === 0 || n === 11 || n === 15) && t.flags & 16384 && (n = t.updateQueue, n !== null && (n = n.stores, n !== null))) for (var r = 0; r < n.length; r++) {
        var i = n[r], a = i.getSnapshot;
        i = i.value;
        try {
          if (!mr(a(), i)) return !1;
        } catch {
          return !1;
        }
      }
      if (n = t.child, t.subtreeFlags & 16384 && n !== null) n.return = t, t = n;
      else {
        if (t === e) break;
        for (; t.sibling === null;) {
          if (t.return === null || t.return === e) return !0;
          t = t.return;
        }
        t.sibling.return = t.return, t = t.sibling;
      }
    }
    return !0;
  }
  function gu(e, t, n, r) {
    t &= ~Wl, t &= ~Ul, e.suspendedLanes |= t, e.pingedLanes &= ~t, r && (e.warmLanes |= t), r = e.expirationTimes;
    for (var i = t; 0 < i;) {
      var a = 31 - He(i), o = 1 << a;
      r[a] = -1, i &= ~o;
    }
    n !== 0 && rt(e, n, t);
  }
  function _u() {
    return jl & 6 ? !0 : (nd(0, !1), !1);
  }
  function vu() {
    if (Nl !== null) {
      if (Fl === 0) var e = Nl.return;
      else e = Nl, Ri = Li = null, bo(e), xa = null, Sa = 0, e = Nl;
      for (; e !== null;) jc(e.alternate, e), e = e.return;
      Nl = null;
    }
  }
  function yu(e, t) {
    var n = e.timeoutHandle;
    n !== -1 && (e.timeoutHandle = -1, qd(n)), n = e.cancelPendingCommit, n !== null && (e.cancelPendingCommit = null, n()), iu = 0, vu(), Ml = e, Nl = n = ei(e.current, null), Pl = t, Fl = 0, Il = null, Ll = !1, Rl = Ze(e, t), zl = !1, Kl = Gl = Wl = Ul = Hl = Vl = 0, Jl = ql = null, Yl = !1, t & 8 && (t |= t & 32);
    var r = e.entangledLanes;
    if (r !== 0) for (e = e.entanglements, r &= t; 0 < r;) {
      var i = 31 - He(r), a = 1 << i;
      t |= e[i], r &= ~a;
    }
    return Bl = t, Wr(), n;
  }
  function bu(e, t) {
    to = null, k.H = Os, t === da || t === pa ? (t = ya(), Fl = 3) : t === fa ? (t = ya(), Fl = 4) : Fl = t === Ks ? 8 : typeof t == "object" && t && typeof t.then == "function" ? 6 : 1, Il = t, Nl === null && (Vl = 1, Bs(e, ci(t, e.current)));
  }
  function xu() {
    var e = Ga.current;
    return e === null ? !0 : (Pl & 4194048) === Pl ? Ka === null : (Pl & 62914560) === Pl || Pl & 536870912 ? e === Ka : !1;
  }
  function Su() {
    var e = k.H;
    return k.H = Os, e === null ? Os : e;
  }
  function Cu() {
    var e = k.A;
    return k.A = kl, e;
  }
  function wu() {
    Vl = 4, Ll || (Pl & 4194048) !== Pl && Ga.current !== null || (Rl = !0), !(Hl & 134217727) && !(Ul & 134217727) || Ml === null || gu(Ml, Pl, Gl, !1);
  }
  function Tu(e, t, n) {
    var r = jl;
    jl |= 2;
    var i = Su(), a = Cu();
    (Ml !== e || Pl !== t) && ($l = null, yu(e, t)), t = !1;
    var o = Vl;
    a: do
      try {
        if (Fl !== 0 && Nl !== null) {
          var s = Nl, c = Il;
          switch (Fl) {
            case 8:
              vu(), o = 6;
              break a;
            case 3:
            case 2:
            case 9:
            case 6:
              Ga.current === null && (t = !0);
              var l = Fl;
              if (Fl = 0, Il = null, ju(e, s, c, l), n && Rl) {
                o = 0;
                break a;
              }
              break;
            default: l = Fl, Fl = 0, Il = null, ju(e, s, c, l);
          }
        }
        Eu(), o = Vl;
        break;
      } catch (t) {
        bu(e, t);
      }
    while (1);
    return t && e.shellSuspendCounter++, Ri = Li = null, jl = r, k.H = i, k.A = a, Nl === null && (Ml = null, Pl = 0, Wr()), o;
  }
  function Eu() {
    for (; Nl !== null;) ku(Nl);
  }
  function Du(e, t) {
    var n = jl;
    jl |= 2;
    var r = Su(), a = Cu();
    Ml !== e || Pl !== t ? ($l = null, Ql = Ae() + 500, yu(e, t)) : Rl = Ze(e, t);
    a: do
      try {
        if (Fl !== 0 && Nl !== null) {
          t = Nl;
          var o = Il;
          b: switch (Fl) {
            case 1:
              Fl = 0, Il = null, ju(e, t, o, 1);
              break;
            case 2:
            case 9:
              if (ha(o)) {
                Fl = 0, Il = null, Au(t);
                break;
              }
              t = function() {
                Fl !== 2 && Fl !== 9 || Ml !== e || (Fl = 7), td(e);
              }, o.then(t, t);
              break a;
            case 3:
              Fl = 7;
              break a;
            case 4:
              Fl = 5;
              break a;
            case 7:
              ha(o) ? (Fl = 0, Il = null, Au(t)) : (Fl = 0, Il = null, ju(e, t, o, 7));
              break;
            case 5:
              var s = null;
              switch (Nl.tag) {
                case 26: s = Nl.memoizedState;
                case 5:
                case 27:
                  var c = Nl;
                  if (s ? Wf(s) : c.stateNode.complete) {
                    Fl = 0, Il = null;
                    var l = c.sibling;
                    if (l !== null) Nl = l;
                    else {
                      var u = c.return;
                      u === null ? Nl = null : (Nl = u, Mu(u));
                    }
                    break b;
                  }
              }
              Fl = 0, Il = null, ju(e, t, o, 5);
              break;
            case 6:
              Fl = 0, Il = null, ju(e, t, o, 6);
              break;
            case 8:
              vu(), Vl = 6;
              break a;
            default: throw Error(i(462));
          }
        }
        Ou();
        break;
      } catch (t) {
        bu(e, t);
      }
    while (1);
    return Ri = Li = null, k.H = r, k.A = a, jl = n, Nl === null ? (Ml = null, Pl = 0, Wr(), Vl) : 0;
  }
  function Ou() {
    for (; Nl !== null && !Oe();) ku(Nl);
  }
  function ku(e) {
    var t = Sc(e.alternate, e, Bl);
    e.memoizedProps = e.pendingProps, t === null ? Mu(e) : Nl = t;
  }
  function Au(e) {
    var t = e, n = t.alternate;
    switch (t.tag) {
      case 15:
      case 0:
        t = oc(n, t, t.pendingProps, t.type, void 0, Pl);
        break;
      case 11:
        t = oc(n, t, t.pendingProps, t.type.render, t.ref, Pl);
        break;
      case 5: bo(t);
      default: jc(n, t), t = Nl = ti(t, Bl), t = Sc(n, t, Bl);
    }
    e.memoizedProps = e.pendingProps, t === null ? Mu(e) : Nl = t;
  }
  function ju(e, t, n, r) {
    Ri = Li = null, bo(t), xa = null, Sa = 0;
    var i = t.return;
    try {
      if (Gs(e, i, t, n, Pl)) {
        Vl = 1, Bs(e, ci(n, e.current)), Nl = null;
        return;
      }
    } catch (t) {
      if (i !== null) throw Nl = i, t;
      Vl = 1, Bs(e, ci(n, e.current)), Nl = null;
      return;
    }
    t.flags & 32768 ? (Ti || r === 1 ? e = !0 : Rl || Pl & 536870912 ? e = !1 : (Ll = e = !0, (r === 2 || r === 9 || r === 3 || r === 6) && (r = Ga.current, r !== null && r.tag === 13 && (r.flags |= 16384))), Nu(t, e)) : Mu(t);
  }
  function Mu(e) {
    var t = e;
    do {
      if (t.flags & 32768) {
        Nu(t, Ll);
        return;
      }
      e = t.return;
      var n = kc(t.alternate, t, Bl);
      if (n !== null) {
        Nl = n;
        return;
      }
      if (t = t.sibling, t !== null) {
        Nl = t;
        return;
      }
      Nl = t = e;
    } while (t !== null);
    Vl === 0 && (Vl = 5);
  }
  function Nu(e, t) {
    do {
      var n = Ac(e.alternate, e);
      if (n !== null) {
        n.flags &= 32767, Nl = n;
        return;
      }
      if (n = e.return, n !== null && (n.flags |= 32768, n.subtreeFlags = 0, n.deletions = null), !t && (e = e.sibling, e !== null)) {
        Nl = e;
        return;
      }
      Nl = e = n;
    } while (e !== null);
    Vl = 6, Nl = null;
  }
  function Pu(e, t, n, r, a, o, s, c, l) {
    e.cancelPendingCommit = null;
    do
      zu();
    while (tu !== 0);
    if (jl & 6) throw Error(i(327));
    if (t !== null) {
      if (t === e.current) throw Error(i(177));
      if (o = t.lanes | t.childLanes, o |= Ur, nt(e, n, o, s, c, l), e === Ml && (Nl = Ml = null, Pl = 0), ru = t, nu = e, iu = n, au = o, ou = a, su = r, t.subtreeFlags & 10256 || t.flags & 10256 ? (e.callbackNode = null, e.callbackPriority = 0, Ju(Pe, function() {
        return Bu(), null;
      })) : (e.callbackNode = null, e.callbackPriority = 0), r = (t.flags & 13878) != 0, t.subtreeFlags & 13878 || r) {
        r = k.T, k.T = null, a = A.p, A.p = 2, s = jl, jl |= 4;
        try {
          Xc(e, t, n);
        } finally {
          jl = s, A.p = a, k.T = r;
        }
      }
      tu = 1, Fu(), Iu(), Lu();
    }
  }
  function Fu() {
    if (tu === 1) {
      tu = 0;
      var e = nu, t = ru, n = (t.flags & 13878) != 0;
      if (t.subtreeFlags & 13878 || n) {
        n = k.T, k.T = null;
        var r = A.p;
        A.p = 2;
        var i = jl;
        jl |= 4;
        try {
          ll(t, e);
          var a = zd, o = yr(e.containerInfo), s = a.focusedElem, c = a.selectionRange;
          if (o !== s && s && s.ownerDocument && vr(s.ownerDocument.documentElement, s)) {
            if (c !== null && br(s)) {
              var l = c.start, u = c.end;
              if (u === void 0 && (u = l), "selectionStart" in s) s.selectionStart = l, s.selectionEnd = Math.min(u, s.value.length);
              else {
                var d = s.ownerDocument || document, f = d && d.defaultView || window;
                if (f.getSelection) {
                  var p = f.getSelection(), m = s.textContent.length, h = Math.min(c.start, m), g = c.end === void 0 ? h : Math.min(c.end, m);
                  !p.extend && h > g && (o = g, g = h, h = o);
                  var _ = _r(s, h), v = _r(s, g);
                  if (_ && v && (p.rangeCount !== 1 || p.anchorNode !== _.node || p.anchorOffset !== _.offset || p.focusNode !== v.node || p.focusOffset !== v.offset)) {
                    var y = d.createRange();
                    y.setStart(_.node, _.offset), p.removeAllRanges(), h > g ? (p.addRange(y), p.extend(v.node, v.offset)) : (y.setEnd(v.node, v.offset), p.addRange(y));
                  }
                }
              }
            }
            for (d = [], p = s; p = p.parentNode;) p.nodeType === 1 && d.push({
              element: p,
              left: p.scrollLeft,
              top: p.scrollTop
            });
            for (typeof s.focus == "function" && s.focus(), s = 0; s < d.length; s++) {
              var b = d[s];
              b.element.scrollLeft = b.left, b.element.scrollTop = b.top;
            }
          }
          sp = !!Rd, zd = Rd = null;
        } finally {
          jl = i, A.p = r, k.T = n;
        }
      }
      e.current = t, tu = 2;
    }
  }
  function Iu() {
    if (tu === 2) {
      tu = 0;
      var e = nu, t = ru, n = (t.flags & 8772) != 0;
      if (t.subtreeFlags & 8772 || n) {
        n = k.T, k.T = null;
        var r = A.p;
        A.p = 2;
        var i = jl;
        jl |= 4;
        try {
          Zc(e, t.alternate, t);
        } finally {
          jl = i, A.p = r, k.T = n;
        }
      }
      tu = 3;
    }
  }
  function Lu() {
    if (tu === 4 || tu === 3) {
      tu = 0, ke();
      var e = nu, t = ru, n = iu, r = su;
      t.subtreeFlags & 10256 || t.flags & 10256 ? tu = 5 : (tu = 0, ru = nu = null, Ru(e, e.pendingLanes));
      var i = e.pendingLanes;
      if (i === 0 && (eu = null), st(n), t = t.stateNode, Be && typeof Be.onCommitFiberRoot == "function") try {
        Be.onCommitFiberRoot(ze, t, void 0, (t.current.flags & 128) == 128);
      } catch {}
      if (r !== null) {
        t = k.T, i = A.p, A.p = 2, k.T = null;
        try {
          for (var a = e.onRecoverableError, o = 0; o < r.length; o++) {
            var s = r[o];
            a(s.value, { componentStack: s.stack });
          }
        } finally {
          k.T = t, A.p = i;
        }
      }
      iu & 3 && zu(), td(e), i = e.pendingLanes, n & 261930 && i & 42 ? e === lu ? cu++ : (cu = 0, lu = e) : cu = 0, nd(0, !1);
    }
  }
  function Ru(e, t) {
    (e.pooledCacheLanes &= t) === 0 && (t = e.pooledCache, t != null && (e.pooledCache = null, $i(t)));
  }
  function zu() {
    return Fu(), Iu(), Lu(), Bu();
  }
  function Bu() {
    if (tu !== 5) return !1;
    var e = nu, t = au;
    au = 0;
    var n = st(iu), r = k.T, a = A.p;
    try {
      A.p = 32 > n ? 32 : n, k.T = null, n = ou, ou = null;
      var o = nu, s = iu;
      if (tu = 0, ru = nu = null, iu = 0, jl & 6) throw Error(i(331));
      var c = jl;
      if (jl |= 4, El(o.current), vl(o, o.current, s, n), jl = c, nd(0, !1), Be && typeof Be.onPostCommitFiberRoot == "function") try {
        Be.onPostCommitFiberRoot(ze, o);
      } catch {}
      return !0;
    } finally {
      A.p = a, k.T = r, Ru(e, t);
    }
  }
  function Vu(e, t, n) {
    t = ci(n, t), t = Hs(e.stateNode, t, 2), e = Na(e, t, 2), e !== null && (tt(e, 2), td(e));
  }
  function Hu(e, t, n) {
    if (e.tag === 3) Vu(e, e, n);
    else for (; t !== null;) {
      if (t.tag === 3) {
        Vu(t, e, n);
        break;
      } else if (t.tag === 1) {
        var r = t.stateNode;
        if (typeof t.type.getDerivedStateFromError == "function" || typeof r.componentDidCatch == "function" && (eu === null || !eu.has(r))) {
          e = ci(n, e), n = Us(2), r = Na(t, n, 2), r !== null && (Ws(n, r, t, e), tt(r, 2), td(r));
          break;
        }
      }
      t = t.return;
    }
  }
  function Uu(e, t, n) {
    var r = e.pingCache;
    if (r === null) {
      r = e.pingCache = new Al();
      var i = /* @__PURE__ */ new Set();
      r.set(t, i);
    } else i = r.get(t), i === void 0 && (i = /* @__PURE__ */ new Set(), r.set(t, i));
    i.has(n) || (zl = !0, i.add(n), e = Wu.bind(null, e, t, n), t.then(e, e));
  }
  function Wu(e, t, n) {
    var r = e.pingCache;
    r !== null && r.delete(t), e.pingedLanes |= e.suspendedLanes & n, e.warmLanes &= ~n, Ml === e && (Pl & n) === n && (Vl === 4 || Vl === 3 && (Pl & 62914560) === Pl && 300 > Ae() - Xl ? !(jl & 2) && yu(e, 0) : Wl |= n, Kl === Pl && (Kl = 0)), td(e);
  }
  function Gu(e, t) {
    t === 0 && (t = $e()), e = qr(e, t), e !== null && (tt(e, t), td(e));
  }
  function Ku(e) {
    var t = e.memoizedState, n = 0;
    t !== null && (n = t.retryLane), Gu(e, n);
  }
  function qu(e, t) {
    var n = 0;
    switch (e.tag) {
      case 31:
      case 13:
        var r = e.stateNode, a = e.memoizedState;
        a !== null && (n = a.retryLane);
        break;
      case 19:
        r = e.stateNode;
        break;
      case 22:
        r = e.stateNode._retryCache;
        break;
      default: throw Error(i(314));
    }
    r !== null && r.delete(t), Gu(e, n);
  }
  function Ju(e, t) {
    return Ee(e, t);
  }
  var Yu = null, Xu = null, Zu = !1, Qu = !1, $u = !1, ed = 0;
  function td(e) {
    e !== Xu && e.next === null && (Xu === null ? Yu = Xu = e : Xu = Xu.next = e), Qu = !0, Zu || (Zu = !0, cd());
  }
  function nd(e, t) {
    if (!$u && Qu) {
      $u = !0;
      do
        for (var n = !1, r = Yu; r !== null;) {
          if (!t) if (e !== 0) {
            var i = r.pendingLanes;
            if (i === 0) var a = 0;
            else {
              var o = r.suspendedLanes, s = r.pingedLanes;
              a = (1 << 31 - He(42 | e) + 1) - 1, a &= i & ~(o & ~s), a = a & 201326741 ? a & 201326741 | 1 : a ? a | 2 : 0;
            }
            a !== 0 && (n = !0, sd(r, a));
          } else a = Pl, a = Xe(r, r === Ml ? a : 0, r.cancelPendingCommit !== null || r.timeoutHandle !== -1), !(a & 3) || Ze(r, a) || (n = !0, sd(r, a));
          r = r.next;
        }
      while (n);
      $u = !1;
    }
  }
  function rd() {
    id();
  }
  function id() {
    Qu = Zu = !1;
    var e = 0;
    ed !== 0 && Gd() && (e = ed);
    for (var t = Ae(), n = null, r = Yu; r !== null;) {
      var i = r.next, a = ad(r, t);
      a === 0 ? (r.next = null, n === null ? Yu = i : n.next = i, i === null && (Xu = n)) : (n = r, (e !== 0 || a & 3) && (Qu = !0)), r = i;
    }
    tu !== 0 && tu !== 5 || nd(e, !1), ed !== 0 && (ed = 0);
  }
  function ad(e, t) {
    for (var n = e.suspendedLanes, r = e.pingedLanes, i = e.expirationTimes, a = e.pendingLanes & -62914561; 0 < a;) {
      var o = 31 - He(a), s = 1 << o, c = i[o];
      c === -1 ? ((s & n) === 0 || (s & r) !== 0) && (i[o] = Qe(s, t)) : c <= t && (e.expiredLanes |= s), a &= ~s;
    }
    if (t = Ml, n = Pl, n = Xe(e, e === t ? n : 0, e.cancelPendingCommit !== null || e.timeoutHandle !== -1), r = e.callbackNode, n === 0 || e === t && (Fl === 2 || Fl === 9) || e.cancelPendingCommit !== null) return r !== null && r !== null && De(r), e.callbackNode = null, e.callbackPriority = 0;
    if (!(n & 3) || Ze(e, n)) {
      if (t = n & -n, t === e.callbackPriority) return t;
      switch (r !== null && De(r), st(n)) {
        case 2:
        case 8:
          n = Ne;
          break;
        case 32:
          n = Pe;
          break;
        case 268435456:
          n = Ie;
          break;
        default: n = Pe;
      }
      return r = od.bind(null, e), n = Ee(n, r), e.callbackPriority = t, e.callbackNode = n, t;
    }
    return r !== null && r !== null && De(r), e.callbackPriority = 2, e.callbackNode = null, 2;
  }
  function od(e, t) {
    if (tu !== 0 && tu !== 5) return e.callbackNode = null, e.callbackPriority = 0, null;
    var n = e.callbackNode;
    if (zu() && e.callbackNode !== n) return null;
    var r = Pl;
    return r = Xe(e, e === Ml ? r : 0, e.cancelPendingCommit !== null || e.timeoutHandle !== -1), r === 0 ? null : (pu(e, r, t), ad(e, Ae()), e.callbackNode != null && e.callbackNode === n ? od.bind(null, e) : null);
  }
  function sd(e, t) {
    if (zu()) return null;
    pu(e, t, !0);
  }
  function cd() {
    Yd(function() {
      jl & 6 ? Ee(Me, rd) : id();
    });
  }
  function ld() {
    if (ed === 0) {
      var e = na;
      e === 0 && (e = Ke, Ke <<= 1, !(Ke & 261888) && (Ke = 256)), ed = e;
    }
    return ed;
  }
  function ud(e) {
    return e == null || typeof e == "symbol" || typeof e == "boolean" ? null : typeof e == "function" ? e : tn("" + e);
  }
  function dd(e, t) {
    var n = t.ownerDocument.createElement("input");
    return n.name = t.name, n.value = t.value, e.id && n.setAttribute("form", e.id), t.parentNode.insertBefore(n, t), e = new FormData(e), n.parentNode.removeChild(n), e;
  }
  function fd(e, t, n, r, i) {
    if (t === "submit" && n && n.stateNode === i) {
      var a = ud((i[ft] || null).action), o = r.submitter;
      o && (t = (t = o[ft] || null) ? ud(t.formAction) : o.getAttribute("formAction"), t !== null && (a = t, o = null));
      var s = new Cn("action", "action", null, r, i);
      e.push({
        event: s,
        listeners: [{
          instance: null,
          listener: function() {
            if (r.defaultPrevented) {
              if (ed !== 0) {
                var e = o ? dd(i, o) : new FormData(i);
                hs(n, {
                  pending: !0,
                  data: e,
                  method: i.method,
                  action: a
                }, null, e);
              }
            } else typeof a == "function" && (s.preventDefault(), e = o ? dd(i, o) : new FormData(i), hs(n, {
              pending: !0,
              data: e,
              method: i.method,
              action: a
            }, a, e));
          },
          currentTarget: i
        }]
      });
    }
  }
  for (var pd = 0; pd < Rr.length; pd++) {
    var md = Rr[pd];
    zr(md.toLowerCase(), "on" + (md[0].toUpperCase() + md.slice(1)));
  }
  zr(Ar, "onAnimationEnd"), zr(jr, "onAnimationIteration"), zr(Mr, "onAnimationStart"), zr("dblclick", "onDoubleClick"), zr("focusin", "onFocus"), zr("focusout", "onBlur"), zr(Nr, "onTransitionRun"), zr(Pr, "onTransitionStart"), zr(Fr, "onTransitionCancel"), zr(Ir, "onTransitionEnd"), Ot("onMouseEnter", ["mouseout", "mouseover"]), Ot("onMouseLeave", ["mouseout", "mouseover"]), Ot("onPointerEnter", ["pointerout", "pointerover"]), Ot("onPointerLeave", ["pointerout", "pointerover"]), Dt("onChange", "change click focusin focusout input keydown keyup selectionchange".split(" ")), Dt("onSelect", "focusout contextmenu dragend focusin keydown keyup mousedown mouseup selectionchange".split(" ")), Dt("onBeforeInput", [
    "compositionend",
    "keypress",
    "textInput",
    "paste"
  ]), Dt("onCompositionEnd", "compositionend focusout keydown keypress keyup mousedown".split(" ")), Dt("onCompositionStart", "compositionstart focusout keydown keypress keyup mousedown".split(" ")), Dt("onCompositionUpdate", "compositionupdate focusout keydown keypress keyup mousedown".split(" "));
  var hd = "abort canplay canplaythrough durationchange emptied encrypted ended error loadeddata loadedmetadata loadstart pause play playing progress ratechange resize seeked seeking stalled suspend timeupdate volumechange waiting".split(" "), gd = new Set("beforetoggle cancel close invalid load scroll scrollend toggle".split(" ").concat(hd));
  function _d(e, t) {
    t = (t & 4) != 0;
    for (var n = 0; n < e.length; n++) {
      var r = e[n], i = r.event;
      r = r.listeners;
      a: {
        var a = void 0;
        if (t) for (var o = r.length - 1; 0 <= o; o--) {
          var s = r[o], c = s.instance, l = s.currentTarget;
          if (s = s.listener, c !== a && i.isPropagationStopped()) break a;
          a = s, i.currentTarget = l;
          try {
            a(i);
          } catch (e) {
            Br(e);
          }
          i.currentTarget = null, a = c;
        }
        else for (o = 0; o < r.length; o++) {
          if (s = r[o], c = s.instance, l = s.currentTarget, s = s.listener, c !== a && i.isPropagationStopped()) break a;
          a = s, i.currentTarget = l;
          try {
            a(i);
          } catch (e) {
            Br(e);
          }
          i.currentTarget = null, a = c;
        }
      }
    }
  }
  function vd(e, t) {
    var n = t[mt];
    n === void 0 && (n = t[mt] = /* @__PURE__ */ new Set());
    var r = e + "__bubble";
    n.has(r) || (Sd(t, e, 2, !1), n.add(r));
  }
  function yd(e, t, n) {
    var r = 0;
    t && (r |= 4), Sd(n, e, r, t);
  }
  var bd = "_reactListening" + Math.random().toString(36).slice(2);
  function xd(e) {
    if (!e[bd]) {
      e[bd] = !0, Tt.forEach(function(t) {
        t !== "selectionchange" && (gd.has(t) || yd(t, !1, e), yd(t, !0, e));
      });
      var t = e.nodeType === 9 ? e : e.ownerDocument;
      t === null || t[bd] || (t[bd] = !0, yd("selectionchange", !1, t));
    }
  }
  function Sd(e, t, n, r) {
    switch (mp(t)) {
      case 2:
        var i = cp;
        break;
      case 8:
        i = lp;
        break;
      default: i = up;
    }
    n = i.bind(null, t, n, e), i = void 0, !pn || t !== "touchstart" && t !== "touchmove" && t !== "wheel" || (i = !0), r ? i === void 0 ? e.addEventListener(t, n, !0) : e.addEventListener(t, n, {
      capture: !0,
      passive: i
    }) : i === void 0 ? e.addEventListener(t, n, !1) : e.addEventListener(t, n, { passive: i });
  }
  function Cd(e, t, n, r, i) {
    var a = r;
    if (!(t & 1) && !(t & 2) && r !== null) a: for (;;) {
      if (r === null) return;
      var s = r.tag;
      if (s === 3 || s === 4) {
        var c = r.stateNode.containerInfo;
        if (c === i) break;
        if (s === 4) for (s = r.return; s !== null;) {
          var l = s.tag;
          if ((l === 3 || l === 4) && s.stateNode.containerInfo === i) return;
          s = s.return;
        }
        for (; c !== null;) {
          if (s = bt(c), s === null) return;
          if (l = s.tag, l === 5 || l === 6 || l === 26 || l === 27) {
            r = a = s;
            continue a;
          }
          c = c.parentNode;
        }
      }
      r = r.return;
    }
    un(function() {
      var r = a, i = an(n), s = [];
      a: {
        var c = Lr.get(e);
        if (c !== void 0) {
          var l = Cn, u = e;
          switch (e) {
            case "keypress": if (vn(n) === 0) break a;
            case "keydown":
            case "keyup":
              l = Bn;
              break;
            case "focusin":
              u = "focus", l = Mn;
              break;
            case "focusout":
              u = "blur", l = Mn;
              break;
            case "beforeblur":
            case "afterblur":
              l = Mn;
              break;
            case "click": if (n.button === 2) break a;
            case "auxclick":
            case "dblclick":
            case "mousedown":
            case "mousemove":
            case "mouseup":
            case "mouseout":
            case "mouseover":
            case "contextmenu":
              l = An;
              break;
            case "drag":
            case "dragend":
            case "dragenter":
            case "dragexit":
            case "dragleave":
            case "dragover":
            case "dragstart":
            case "drop":
              l = jn;
              break;
            case "touchcancel":
            case "touchend":
            case "touchmove":
            case "touchstart":
              l = Hn;
              break;
            case Ar:
            case jr:
            case Mr:
              l = Nn;
              break;
            case Ir:
              l = Un;
              break;
            case "scroll":
            case "scrollend":
              l = Tn;
              break;
            case "wheel":
              l = Wn;
              break;
            case "copy":
            case "cut":
            case "paste":
              l = Pn;
              break;
            case "gotpointercapture":
            case "lostpointercapture":
            case "pointercancel":
            case "pointerdown":
            case "pointermove":
            case "pointerout":
            case "pointerover":
            case "pointerup":
              l = Vn;
              break;
            case "toggle":
            case "beforetoggle": l = Gn;
          }
          var d = (t & 4) != 0, f = !d && (e === "scroll" || e === "scrollend"), p = d ? c === null ? null : c + "Capture" : c;
          d = [];
          for (var m = r, h; m !== null;) {
            var g = m;
            if (h = g.stateNode, g = g.tag, g !== 5 && g !== 26 && g !== 27 || h === null || p === null || (g = dn(m, p), g != null && d.push(wd(m, g, h))), f) break;
            m = m.return;
          }
          0 < d.length && (c = new l(c, u, null, n, i), s.push({
            event: c,
            listeners: d
          }));
        }
      }
      if (!(t & 7)) {
        a: {
          if (c = e === "mouseover" || e === "pointerover", l = e === "mouseout" || e === "pointerout", c && n !== rn && (u = n.relatedTarget || n.fromElement) && (bt(u) || u[pt])) break a;
          if ((l || c) && (c = i.window === i ? i : (c = i.ownerDocument) ? c.defaultView || c.parentWindow : window, l ? (u = n.relatedTarget || n.toElement, l = r, u = u ? bt(u) : null, u !== null && (f = o(u), d = u.tag, u !== f || d !== 5 && d !== 27 && d !== 6) && (u = null)) : (l = null, u = r), l !== u)) {
            if (d = An, g = "onMouseLeave", p = "onMouseEnter", m = "mouse", (e === "pointerout" || e === "pointerover") && (d = Vn, g = "onPointerLeave", p = "onPointerEnter", m = "pointer"), f = l == null ? c : St(l), h = u == null ? c : St(u), c = new d(g, m + "leave", l, n, i), c.target = f, c.relatedTarget = h, g = null, bt(i) === r && (d = new d(p, m + "enter", u, n, i), d.target = h, d.relatedTarget = f, g = d), f = g, l && u) b: {
              for (d = Ed, p = l, m = u, h = 0, g = p; g; g = d(g)) h++;
              g = 0;
              for (var _ = m; _; _ = d(_)) g++;
              for (; 0 < h - g;) p = d(p), h--;
              for (; 0 < g - h;) m = d(m), g--;
              for (; h--;) {
                if (p === m || m !== null && p === m.alternate) {
                  d = p;
                  break b;
                }
                p = d(p), m = d(m);
              }
              d = null;
            }
            else d = null;
            l !== null && Dd(s, c, l, d, !1), u !== null && f !== null && Dd(s, f, u, d, !0);
          }
        }
        a: {
          if (c = r ? St(r) : window, l = c.nodeName && c.nodeName.toLowerCase(), l === "select" || l === "input" && c.type === "file") var v = V;
          else if (ar(c)) if (cr) v = G;
          else {
            v = U;
            var y = H;
          }
          else l = c.nodeName, !l || l.toLowerCase() !== "input" || c.type !== "checkbox" && c.type !== "radio" ? r && Qt(r.elementType) && (v = V) : v = W;
          if (v &&= v(e, r)) {
            R(s, v, n, i);
            break a;
          }
          y && y(e, c, r), e === "focusout" && r && c.type === "number" && r.memoizedProps.value != null && Gt(c, "number", c.value);
        }
        switch (y = r ? St(r) : window, e) {
          case "focusin":
            (ar(y) || y.contentEditable === "true") && (Sr = y, Cr = r, wr = null);
            break;
          case "focusout":
            wr = Cr = Sr = null;
            break;
          case "mousedown":
            Tr = !0;
            break;
          case "contextmenu":
          case "mouseup":
          case "dragend":
            Tr = !1, Er(s, n, i);
            break;
          case "selectionchange": if (xr) break;
          case "keydown":
          case "keyup": Er(s, n, i);
        }
        var b;
        if (qn) b: {
          switch (e) {
            case "compositionstart":
              var x = "onCompositionStart";
              break b;
            case "compositionend":
              x = "onCompositionEnd";
              break b;
            case "compositionupdate":
              x = "onCompositionUpdate";
              break b;
          }
          x = void 0;
        }
        else tr ? $n(e, n) && (x = "onCompositionEnd") : e === "keydown" && n.keyCode === 229 && (x = "onCompositionStart");
        x && (Xn && n.locale !== "ko" && (tr || x !== "onCompositionStart" ? x === "onCompositionEnd" && tr && (b = _n()) : (mn = i, hn = "value" in mn ? mn.value : mn.textContent, tr = !0)), y = Td(r, x), 0 < y.length && (x = new Fn(x, e, null, n, i), s.push({
          event: x,
          listeners: y
        }), b ? x.data = b : (b = er(n), b !== null && (x.data = b)))), (b = Yn ? nr(e, n) : rr(e, n)) && (x = Td(r, "onBeforeInput"), 0 < x.length && (y = new Fn("onBeforeInput", "beforeinput", null, n, i), s.push({
          event: y,
          listeners: x
        }), y.data = b)), fd(s, e, r, n, i);
      }
      _d(s, t);
    });
  }
  function wd(e, t, n) {
    return {
      instance: e,
      listener: t,
      currentTarget: n
    };
  }
  function Td(e, t) {
    for (var n = t + "Capture", r = []; e !== null;) {
      var i = e, a = i.stateNode;
      if (i = i.tag, i !== 5 && i !== 26 && i !== 27 || a === null || (i = dn(e, n), i != null && r.unshift(wd(e, i, a)), i = dn(e, t), i != null && r.push(wd(e, i, a))), e.tag === 3) return r;
      e = e.return;
    }
    return [];
  }
  function Ed(e) {
    if (e === null) return null;
    do
      e = e.return;
    while (e && e.tag !== 5 && e.tag !== 27);
    return e || null;
  }
  function Dd(e, t, n, r, i) {
    for (var a = t._reactName, o = []; n !== null && n !== r;) {
      var s = n, c = s.alternate, l = s.stateNode;
      if (s = s.tag, c !== null && c === r) break;
      s !== 5 && s !== 26 && s !== 27 || l === null || (c = l, i ? (l = dn(n, a), l != null && o.unshift(wd(n, l, c))) : i || (l = dn(n, a), l != null && o.push(wd(n, l, c)))), n = n.return;
    }
    o.length !== 0 && e.push({
      event: t,
      listeners: o
    });
  }
  var Od = /\r\n?/g, kd = /\u0000|\uFFFD/g;
  function Ad(e) {
    return (typeof e == "string" ? e : "" + e).replace(Od, "\n").replace(kd, "");
  }
  function jd(e, t) {
    return t = Ad(t), Ad(e) === t;
  }
  function Md(e, t, n, r, a, o) {
    switch (n) {
      case "children":
        typeof r == "string" ? t === "body" || t === "textarea" && r === "" || Jt(e, r) : (typeof r == "number" || typeof r == "bigint") && t !== "body" && Jt(e, "" + r);
        break;
      case "className":
        Pt(e, "class", r);
        break;
      case "tabIndex":
        Pt(e, "tabindex", r);
        break;
      case "dir":
      case "role":
      case "viewBox":
      case "width":
      case "height":
        Pt(e, n, r);
        break;
      case "style":
        Zt(e, r, o);
        break;
      case "data": if (t !== "object") {
        Pt(e, "data", r);
        break;
      }
      case "src":
      case "href":
        if (r === "" && (t !== "a" || n !== "href")) {
          e.removeAttribute(n);
          break;
        }
        if (r == null || typeof r == "function" || typeof r == "symbol" || typeof r == "boolean") {
          e.removeAttribute(n);
          break;
        }
        r = tn("" + r), e.setAttribute(n, r);
        break;
      case "action":
      case "formAction":
        if (typeof r == "function") {
          e.setAttribute(n, "javascript:throw new Error('A React form was unexpectedly submitted. If you called form.submit() manually, consider using form.requestSubmit() instead. If you\\'re trying to use event.stopPropagation() in a submit event handler, consider also calling event.preventDefault().')");
          break;
        } else typeof o == "function" && (n === "formAction" ? (t !== "input" && Md(e, t, "name", a.name, a, null), Md(e, t, "formEncType", a.formEncType, a, null), Md(e, t, "formMethod", a.formMethod, a, null), Md(e, t, "formTarget", a.formTarget, a, null)) : (Md(e, t, "encType", a.encType, a, null), Md(e, t, "method", a.method, a, null), Md(e, t, "target", a.target, a, null)));
        if (r == null || typeof r == "symbol" || typeof r == "boolean") {
          e.removeAttribute(n);
          break;
        }
        r = tn("" + r), e.setAttribute(n, r);
        break;
      case "onClick":
        r != null && (e.onclick = nn);
        break;
      case "onScroll":
        r != null && vd("scroll", e);
        break;
      case "onScrollEnd":
        r != null && vd("scrollend", e);
        break;
      case "dangerouslySetInnerHTML":
        if (r != null) {
          if (typeof r != "object" || !("__html" in r)) throw Error(i(61));
          if (n = r.__html, n != null) {
            if (a.children != null) throw Error(i(60));
            e.innerHTML = n;
          }
        }
        break;
      case "multiple":
        e.multiple = r && typeof r != "function" && typeof r != "symbol";
        break;
      case "muted":
        e.muted = r && typeof r != "function" && typeof r != "symbol";
        break;
      case "suppressContentEditableWarning":
      case "suppressHydrationWarning":
      case "defaultValue":
      case "defaultChecked":
      case "innerHTML":
      case "ref": break;
      case "autoFocus": break;
      case "xlinkHref":
        if (r == null || typeof r == "function" || typeof r == "boolean" || typeof r == "symbol") {
          e.removeAttribute("xlink:href");
          break;
        }
        n = tn("" + r), e.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", n);
        break;
      case "contentEditable":
      case "spellCheck":
      case "draggable":
      case "value":
      case "autoReverse":
      case "externalResourcesRequired":
      case "focusable":
      case "preserveAlpha":
        r != null && typeof r != "function" && typeof r != "symbol" ? e.setAttribute(n, "" + r) : e.removeAttribute(n);
        break;
      case "inert":
      case "allowFullScreen":
      case "async":
      case "autoPlay":
      case "controls":
      case "default":
      case "defer":
      case "disabled":
      case "disablePictureInPicture":
      case "disableRemotePlayback":
      case "formNoValidate":
      case "hidden":
      case "loop":
      case "noModule":
      case "noValidate":
      case "open":
      case "playsInline":
      case "readOnly":
      case "required":
      case "reversed":
      case "scoped":
      case "seamless":
      case "itemScope":
        r && typeof r != "function" && typeof r != "symbol" ? e.setAttribute(n, "") : e.removeAttribute(n);
        break;
      case "capture":
      case "download":
        !0 === r ? e.setAttribute(n, "") : !1 !== r && r != null && typeof r != "function" && typeof r != "symbol" ? e.setAttribute(n, r) : e.removeAttribute(n);
        break;
      case "cols":
      case "rows":
      case "size":
      case "span":
        r != null && typeof r != "function" && typeof r != "symbol" && !isNaN(r) && 1 <= r ? e.setAttribute(n, r) : e.removeAttribute(n);
        break;
      case "rowSpan":
      case "start":
        r == null || typeof r == "function" || typeof r == "symbol" || isNaN(r) ? e.removeAttribute(n) : e.setAttribute(n, r);
        break;
      case "popover":
        vd("beforetoggle", e), vd("toggle", e), Nt(e, "popover", r);
        break;
      case "xlinkActuate":
        Ft(e, "http://www.w3.org/1999/xlink", "xlink:actuate", r);
        break;
      case "xlinkArcrole":
        Ft(e, "http://www.w3.org/1999/xlink", "xlink:arcrole", r);
        break;
      case "xlinkRole":
        Ft(e, "http://www.w3.org/1999/xlink", "xlink:role", r);
        break;
      case "xlinkShow":
        Ft(e, "http://www.w3.org/1999/xlink", "xlink:show", r);
        break;
      case "xlinkTitle":
        Ft(e, "http://www.w3.org/1999/xlink", "xlink:title", r);
        break;
      case "xlinkType":
        Ft(e, "http://www.w3.org/1999/xlink", "xlink:type", r);
        break;
      case "xmlBase":
        Ft(e, "http://www.w3.org/XML/1998/namespace", "xml:base", r);
        break;
      case "xmlLang":
        Ft(e, "http://www.w3.org/XML/1998/namespace", "xml:lang", r);
        break;
      case "xmlSpace":
        Ft(e, "http://www.w3.org/XML/1998/namespace", "xml:space", r);
        break;
      case "is":
        Nt(e, "is", r);
        break;
      case "innerText":
      case "textContent": break;
      default: (!(2 < n.length) || n[0] !== "o" && n[0] !== "O" || n[1] !== "n" && n[1] !== "N") && (n = $t.get(n) || n, Nt(e, n, r));
    }
  }
  function Nd(e, t, n, r, a, o) {
    switch (n) {
      case "style":
        Zt(e, r, o);
        break;
      case "dangerouslySetInnerHTML":
        if (r != null) {
          if (typeof r != "object" || !("__html" in r)) throw Error(i(61));
          if (n = r.__html, n != null) {
            if (a.children != null) throw Error(i(60));
            e.innerHTML = n;
          }
        }
        break;
      case "children":
        typeof r == "string" ? Jt(e, r) : (typeof r == "number" || typeof r == "bigint") && Jt(e, "" + r);
        break;
      case "onScroll":
        r != null && vd("scroll", e);
        break;
      case "onScrollEnd":
        r != null && vd("scrollend", e);
        break;
      case "onClick":
        r != null && (e.onclick = nn);
        break;
      case "suppressContentEditableWarning":
      case "suppressHydrationWarning":
      case "innerHTML":
      case "ref": break;
      case "innerText":
      case "textContent": break;
      default: if (!Et.hasOwnProperty(n)) a: {
        if (n[0] === "o" && n[1] === "n" && (a = n.endsWith("Capture"), t = n.slice(2, a ? n.length - 7 : void 0), o = e[ft] || null, o = o == null ? null : o[n], typeof o == "function" && e.removeEventListener(t, o, a), typeof r == "function")) {
          typeof o != "function" && o !== null && (n in e ? e[n] = null : e.hasAttribute(n) && e.removeAttribute(n)), e.addEventListener(t, r, a);
          break a;
        }
        n in e ? e[n] = r : !0 === r ? e.setAttribute(n, "") : Nt(e, n, r);
      }
    }
  }
  function Pd(e, t, n) {
    switch (t) {
      case "div":
      case "span":
      case "svg":
      case "path":
      case "a":
      case "g":
      case "p":
      case "li": break;
      case "img":
        vd("error", e), vd("load", e);
        var r = !1, a = !1, o;
        for (o in n) if (n.hasOwnProperty(o)) {
          var s = n[o];
          if (s != null) switch (o) {
            case "src":
              r = !0;
              break;
            case "srcSet":
              a = !0;
              break;
            case "children":
            case "dangerouslySetInnerHTML": throw Error(i(137, t));
            default: Md(e, t, o, s, n, null);
          }
        }
        a && Md(e, t, "srcSet", n.srcSet, n, null), r && Md(e, t, "src", n.src, n, null);
        return;
      case "input":
        vd("invalid", e);
        var c = o = s = a = null, l = null, u = null;
        for (r in n) if (n.hasOwnProperty(r)) {
          var d = n[r];
          if (d != null) switch (r) {
            case "name":
              a = d;
              break;
            case "type":
              s = d;
              break;
            case "checked":
              l = d;
              break;
            case "defaultChecked":
              u = d;
              break;
            case "value":
              o = d;
              break;
            case "defaultValue":
              c = d;
              break;
            case "children":
            case "dangerouslySetInnerHTML":
              if (d != null) throw Error(i(137, t));
              break;
            default: Md(e, t, r, d, n, null);
          }
        }
        Wt(e, o, c, l, u, s, a, !1);
        return;
      case "select":
        for (a in vd("invalid", e), r = s = o = null, n) if (n.hasOwnProperty(a) && (c = n[a], c != null)) switch (a) {
          case "value":
            o = c;
            break;
          case "defaultValue":
            s = c;
            break;
          case "multiple": r = c;
          default: Md(e, t, a, c, n, null);
        }
        t = o, n = s, e.multiple = !!r, t == null ? n != null && Kt(e, !!r, n, !0) : Kt(e, !!r, t, !1);
        return;
      case "textarea":
        for (s in vd("invalid", e), o = a = r = null, n) if (n.hasOwnProperty(s) && (c = n[s], c != null)) switch (s) {
          case "value":
            r = c;
            break;
          case "defaultValue":
            a = c;
            break;
          case "children":
            o = c;
            break;
          case "dangerouslySetInnerHTML":
            if (c != null) throw Error(i(91));
            break;
          default: Md(e, t, s, c, n, null);
        }
        qt(e, r, a, o);
        return;
      case "option":
        for (l in n) if (n.hasOwnProperty(l) && (r = n[l], r != null)) switch (l) {
          case "selected":
            e.selected = r && typeof r != "function" && typeof r != "symbol";
            break;
          default: Md(e, t, l, r, n, null);
        }
        return;
      case "dialog":
        vd("beforetoggle", e), vd("toggle", e), vd("cancel", e), vd("close", e);
        break;
      case "iframe":
      case "object":
        vd("load", e);
        break;
      case "video":
      case "audio":
        for (r = 0; r < hd.length; r++) vd(hd[r], e);
        break;
      case "image":
        vd("error", e), vd("load", e);
        break;
      case "details":
        vd("toggle", e);
        break;
      case "embed":
      case "source":
      case "link": vd("error", e), vd("load", e);
      case "area":
      case "base":
      case "br":
      case "col":
      case "hr":
      case "keygen":
      case "meta":
      case "param":
      case "track":
      case "wbr":
      case "menuitem":
        for (u in n) if (n.hasOwnProperty(u) && (r = n[u], r != null)) switch (u) {
          case "children":
          case "dangerouslySetInnerHTML": throw Error(i(137, t));
          default: Md(e, t, u, r, n, null);
        }
        return;
      default: if (Qt(t)) {
        for (d in n) n.hasOwnProperty(d) && (r = n[d], r !== void 0 && Nd(e, t, d, r, n, void 0));
        return;
      }
    }
    for (c in n) n.hasOwnProperty(c) && (r = n[c], r != null && Md(e, t, c, r, n, null));
  }
  function Fd(e, t, n, r) {
    switch (t) {
      case "div":
      case "span":
      case "svg":
      case "path":
      case "a":
      case "g":
      case "p":
      case "li": break;
      case "input":
        var a = null, o = null, s = null, c = null, l = null, u = null, d = null;
        for (m in n) {
          var f = n[m];
          if (n.hasOwnProperty(m) && f != null) switch (m) {
            case "checked": break;
            case "value": break;
            case "defaultValue": l = f;
            default: r.hasOwnProperty(m) || Md(e, t, m, null, r, f);
          }
        }
        for (var p in r) {
          var m = r[p];
          if (f = n[p], r.hasOwnProperty(p) && (m != null || f != null)) switch (p) {
            case "type":
              o = m;
              break;
            case "name":
              a = m;
              break;
            case "checked":
              u = m;
              break;
            case "defaultChecked":
              d = m;
              break;
            case "value":
              s = m;
              break;
            case "defaultValue":
              c = m;
              break;
            case "children":
            case "dangerouslySetInnerHTML":
              if (m != null) throw Error(i(137, t));
              break;
            default: m !== f && Md(e, t, p, m, r, f);
          }
        }
        Ut(e, s, c, l, u, d, o, a);
        return;
      case "select":
        for (o in m = s = c = p = null, n) if (l = n[o], n.hasOwnProperty(o) && l != null) switch (o) {
          case "value": break;
          case "multiple": m = l;
          default: r.hasOwnProperty(o) || Md(e, t, o, null, r, l);
        }
        for (a in r) if (o = r[a], l = n[a], r.hasOwnProperty(a) && (o != null || l != null)) switch (a) {
          case "value":
            p = o;
            break;
          case "defaultValue":
            c = o;
            break;
          case "multiple": s = o;
          default: o !== l && Md(e, t, a, o, r, l);
        }
        t = c, n = s, r = m, p == null ? !!r != !!n && (t == null ? Kt(e, !!n, n ? [] : "", !1) : Kt(e, !!n, t, !0)) : Kt(e, !!n, p, !1);
        return;
      case "textarea":
        for (c in m = p = null, n) if (a = n[c], n.hasOwnProperty(c) && a != null && !r.hasOwnProperty(c)) switch (c) {
          case "value": break;
          case "children": break;
          default: Md(e, t, c, null, r, a);
        }
        for (s in r) if (a = r[s], o = n[s], r.hasOwnProperty(s) && (a != null || o != null)) switch (s) {
          case "value":
            p = a;
            break;
          case "defaultValue":
            m = a;
            break;
          case "children": break;
          case "dangerouslySetInnerHTML":
            if (a != null) throw Error(i(91));
            break;
          default: a !== o && Md(e, t, s, a, r, o);
        }
        F(e, p, m);
        return;
      case "option":
        for (var h in n) if (p = n[h], n.hasOwnProperty(h) && p != null && !r.hasOwnProperty(h)) switch (h) {
          case "selected":
            e.selected = !1;
            break;
          default: Md(e, t, h, null, r, p);
        }
        for (l in r) if (p = r[l], m = n[l], r.hasOwnProperty(l) && p !== m && (p != null || m != null)) switch (l) {
          case "selected":
            e.selected = p && typeof p != "function" && typeof p != "symbol";
            break;
          default: Md(e, t, l, p, r, m);
        }
        return;
      case "img":
      case "link":
      case "area":
      case "base":
      case "br":
      case "col":
      case "embed":
      case "hr":
      case "keygen":
      case "meta":
      case "param":
      case "source":
      case "track":
      case "wbr":
      case "menuitem":
        for (var g in n) p = n[g], n.hasOwnProperty(g) && p != null && !r.hasOwnProperty(g) && Md(e, t, g, null, r, p);
        for (u in r) if (p = r[u], m = n[u], r.hasOwnProperty(u) && p !== m && (p != null || m != null)) switch (u) {
          case "children":
          case "dangerouslySetInnerHTML":
            if (p != null) throw Error(i(137, t));
            break;
          default: Md(e, t, u, p, r, m);
        }
        return;
      default: if (Qt(t)) {
        for (var _ in n) p = n[_], n.hasOwnProperty(_) && p !== void 0 && !r.hasOwnProperty(_) && Nd(e, t, _, void 0, r, p);
        for (d in r) p = r[d], m = n[d], !r.hasOwnProperty(d) || p === m || p === void 0 && m === void 0 || Nd(e, t, d, p, r, m);
        return;
      }
    }
    for (var v in n) p = n[v], n.hasOwnProperty(v) && p != null && !r.hasOwnProperty(v) && Md(e, t, v, null, r, p);
    for (f in r) p = r[f], m = n[f], !r.hasOwnProperty(f) || p === m || p == null && m == null || Md(e, t, f, p, r, m);
  }
  function Id(e) {
    switch (e) {
      case "css":
      case "script":
      case "font":
      case "img":
      case "image":
      case "input":
      case "link": return !0;
      default: return !1;
    }
  }
  function Ld() {
    if (typeof performance.getEntriesByType == "function") {
      for (var e = 0, t = 0, n = performance.getEntriesByType("resource"), r = 0; r < n.length; r++) {
        var i = n[r], a = i.transferSize, o = i.initiatorType, s = i.duration;
        if (a && s && Id(o)) {
          for (o = 0, s = i.responseEnd, r += 1; r < n.length; r++) {
            var c = n[r], l = c.startTime;
            if (l > s) break;
            var u = c.transferSize, d = c.initiatorType;
            u && Id(d) && (c = c.responseEnd, o += u * (c < s ? 1 : (s - l) / (c - l)));
          }
          if (--r, t += 8 * (a + o) / (i.duration / 1e3), e++, 10 < e) break;
        }
      }
      if (0 < e) return t / e / 1e6;
    }
    return navigator.connection && (e = navigator.connection.downlink, typeof e == "number") ? e : 5;
  }
  var Rd = null, zd = null;
  function Bd(e) {
    return e.nodeType === 9 ? e : e.ownerDocument;
  }
  function Vd(e) {
    switch (e) {
      case "http://www.w3.org/2000/svg": return 1;
      case "http://www.w3.org/1998/Math/MathML": return 2;
      default: return 0;
    }
  }
  function Hd(e, t) {
    if (e === 0) switch (t) {
      case "svg": return 1;
      case "math": return 2;
      default: return 0;
    }
    return e === 1 && t === "foreignObject" ? 0 : e;
  }
  function Ud(e, t) {
    return e === "textarea" || e === "noscript" || typeof t.children == "string" || typeof t.children == "number" || typeof t.children == "bigint" || typeof t.dangerouslySetInnerHTML == "object" && t.dangerouslySetInnerHTML !== null && t.dangerouslySetInnerHTML.__html != null;
  }
  var Wd = null;
  function Gd() {
    var e = window.event;
    return e && e.type === "popstate" ? e === Wd ? !1 : (Wd = e, !0) : (Wd = null, !1);
  }
  var Kd = typeof setTimeout == "function" ? setTimeout : void 0, qd = typeof clearTimeout == "function" ? clearTimeout : void 0, Jd = typeof Promise == "function" ? Promise : void 0, Yd = typeof queueMicrotask == "function" ? queueMicrotask : Jd === void 0 ? Kd : function(e) {
    return Jd.resolve(null).then(e).catch(Xd);
  };
  function Xd(e) {
    setTimeout(function() {
      throw e;
    });
  }
  function Zd(e) {
    return e === "head";
  }
  function Qd(e, t) {
    var n = t, r = 0;
    do {
      var i = n.nextSibling;
      if (e.removeChild(n), i && i.nodeType === 8) if (n = i.data, n === "/$" || n === "/&") {
        if (r === 0) {
          e.removeChild(i), Np(t);
          return;
        }
        r--;
      } else if (n === "$" || n === "$?" || n === "$~" || n === "$!" || n === "&") r++;
      else if (n === "html") pf(e.ownerDocument.documentElement);
      else if (n === "head") {
        n = e.ownerDocument.head, pf(n);
        for (var a = n.firstChild; a;) {
          var o = a.nextSibling, s = a.nodeName;
          a[vt] || s === "SCRIPT" || s === "STYLE" || s === "LINK" && a.rel.toLowerCase() === "stylesheet" || n.removeChild(a), a = o;
        }
      } else n === "body" && pf(e.ownerDocument.body);
      n = i;
    } while (n);
    Np(t);
  }
  function $d(e, t) {
    var n = e;
    e = 0;
    do {
      var r = n.nextSibling;
      if (n.nodeType === 1 ? t ? (n._stashedDisplay = n.style.display, n.style.display = "none") : (n.style.display = n._stashedDisplay || "", n.getAttribute("style") === "" && n.removeAttribute("style")) : n.nodeType === 3 && (t ? (n._stashedText = n.nodeValue, n.nodeValue = "") : n.nodeValue = n._stashedText || ""), r && r.nodeType === 8) if (n = r.data, n === "/$") {
        if (e === 0) break;
        e--;
      } else n !== "$" && n !== "$?" && n !== "$~" && n !== "$!" || e++;
      n = r;
    } while (n);
  }
  function ef(e) {
    var t = e.firstChild;
    for (t && t.nodeType === 10 && (t = t.nextSibling); t;) {
      var n = t;
      switch (t = t.nextSibling, n.nodeName) {
        case "HTML":
        case "HEAD":
        case "BODY":
          ef(n), yt(n);
          continue;
        case "SCRIPT":
        case "STYLE": continue;
        case "LINK": if (n.rel.toLowerCase() === "stylesheet") continue;
      }
      e.removeChild(n);
    }
  }
  function tf(e, t, n, r) {
    for (; e.nodeType === 1;) {
      var i = n;
      if (e.nodeName.toLowerCase() !== t.toLowerCase()) {
        if (!r && (e.nodeName !== "INPUT" || e.type !== "hidden")) break;
      } else if (!r) if (t === "input" && e.type === "hidden") {
        var a = i.name == null ? null : "" + i.name;
        if (i.type === "hidden" && e.getAttribute("name") === a) return e;
      } else return e;
      else if (!e[vt]) switch (t) {
        case "meta":
          if (!e.hasAttribute("itemprop")) break;
          return e;
        case "link":
          if (a = e.getAttribute("rel"), a === "stylesheet" && e.hasAttribute("data-precedence") || a !== i.rel || e.getAttribute("href") !== (i.href == null || i.href === "" ? null : i.href) || e.getAttribute("crossorigin") !== (i.crossOrigin == null ? null : i.crossOrigin) || e.getAttribute("title") !== (i.title == null ? null : i.title)) break;
          return e;
        case "style":
          if (e.hasAttribute("data-precedence")) break;
          return e;
        case "script":
          if (a = e.getAttribute("src"), (a !== (i.src == null ? null : i.src) || e.getAttribute("type") !== (i.type == null ? null : i.type) || e.getAttribute("crossorigin") !== (i.crossOrigin == null ? null : i.crossOrigin)) && a && e.hasAttribute("async") && !e.hasAttribute("itemprop")) break;
          return e;
        default: return e;
      }
      if (e = cf(e.nextSibling), e === null) break;
    }
    return null;
  }
  function nf(e, t, n) {
    if (t === "") return null;
    for (; e.nodeType !== 3;) if ((e.nodeType !== 1 || e.nodeName !== "INPUT" || e.type !== "hidden") && !n || (e = cf(e.nextSibling), e === null)) return null;
    return e;
  }
  function rf(e, t) {
    for (; e.nodeType !== 8;) if ((e.nodeType !== 1 || e.nodeName !== "INPUT" || e.type !== "hidden") && !t || (e = cf(e.nextSibling), e === null)) return null;
    return e;
  }
  function af(e) {
    return e.data === "$?" || e.data === "$~";
  }
  function of(e) {
    return e.data === "$!" || e.data === "$?" && e.ownerDocument.readyState !== "loading";
  }
  function sf(e, t) {
    var n = e.ownerDocument;
    if (e.data === "$~") e._reactRetry = t;
    else if (e.data !== "$?" || n.readyState !== "loading") t();
    else {
      var r = function() {
        t(), n.removeEventListener("DOMContentLoaded", r);
      };
      n.addEventListener("DOMContentLoaded", r), e._reactRetry = r;
    }
  }
  function cf(e) {
    for (; e != null; e = e.nextSibling) {
      var t = e.nodeType;
      if (t === 1 || t === 3) break;
      if (t === 8) {
        if (t = e.data, t === "$" || t === "$!" || t === "$?" || t === "$~" || t === "&" || t === "F!" || t === "F") break;
        if (t === "/$" || t === "/&") return null;
      }
    }
    return e;
  }
  var lf = null;
  function uf(e) {
    e = e.nextSibling;
    for (var t = 0; e;) {
      if (e.nodeType === 8) {
        var n = e.data;
        if (n === "/$" || n === "/&") {
          if (t === 0) return cf(e.nextSibling);
          t--;
        } else n !== "$" && n !== "$!" && n !== "$?" && n !== "$~" && n !== "&" || t++;
      }
      e = e.nextSibling;
    }
    return null;
  }
  function df(e) {
    e = e.previousSibling;
    for (var t = 0; e;) {
      if (e.nodeType === 8) {
        var n = e.data;
        if (n === "$" || n === "$!" || n === "$?" || n === "$~" || n === "&") {
          if (t === 0) return e;
          t--;
        } else n !== "/$" && n !== "/&" || t++;
      }
      e = e.previousSibling;
    }
    return null;
  }
  function ff(e, t, n) {
    switch (t = Bd(n), e) {
      case "html":
        if (e = t.documentElement, !e) throw Error(i(452));
        return e;
      case "head":
        if (e = t.head, !e) throw Error(i(453));
        return e;
      case "body":
        if (e = t.body, !e) throw Error(i(454));
        return e;
      default: throw Error(i(451));
    }
  }
  function pf(e) {
    for (var t = e.attributes; t.length;) e.removeAttributeNode(t[0]);
    yt(e);
  }
  var mf = /* @__PURE__ */ new Map(), hf = /* @__PURE__ */ new Set();
  function gf(e) {
    return typeof e.getRootNode == "function" ? e.getRootNode() : e.nodeType === 9 ? e : e.ownerDocument;
  }
  var _f = A.d;
  A.d = {
    f: vf,
    r: yf,
    D: Sf,
    C: Cf,
    L: wf,
    m: Tf,
    X: Df,
    S: Ef,
    M: Of
  };
  function vf() {
    var e = _f.f(), t = _u();
    return e || t;
  }
  function yf(e) {
    var t = xt(e);
    t !== null && t.tag === 5 && t.type === "form" ? _s(t) : _f.r(e);
  }
  var bf = typeof document > "u" ? null : document;
  function xf(e, t, n) {
    var r = bf;
    if (r && typeof t == "string" && t) {
      var i = Ht(t);
      i = "link[rel=\"" + e + "\"][href=\"" + i + "\"]", typeof n == "string" && (i += "[crossorigin=\"" + n + "\"]"), hf.has(i) || (hf.add(i), e = {
        rel: e,
        crossOrigin: n,
        href: t
      }, r.querySelector(i) === null && (t = r.createElement("link"), Pd(t, "link", e), wt(t), r.head.appendChild(t)));
    }
  }
  function Sf(e) {
    _f.D(e), xf("dns-prefetch", e, null);
  }
  function Cf(e, t) {
    _f.C(e, t), xf("preconnect", e, t);
  }
  function wf(e, t, n) {
    _f.L(e, t, n);
    var r = bf;
    if (r && e && t) {
      var i = "link[rel=\"preload\"][as=\"" + Ht(t) + "\"]";
      t === "image" && n && n.imageSrcSet ? (i += "[imagesrcset=\"" + Ht(n.imageSrcSet) + "\"]", typeof n.imageSizes == "string" && (i += "[imagesizes=\"" + Ht(n.imageSizes) + "\"]")) : i += "[href=\"" + Ht(e) + "\"]";
      var a = i;
      switch (t) {
        case "style":
          a = Af(e);
          break;
        case "script": a = Pf(e);
      }
      mf.has(a) || (e = h({
        rel: "preload",
        href: t === "image" && n && n.imageSrcSet ? void 0 : e,
        as: t
      }, n), mf.set(a, e), r.querySelector(i) !== null || t === "style" && r.querySelector(jf(a)) || t === "script" && r.querySelector(Ff(a)) || (t = r.createElement("link"), Pd(t, "link", e), wt(t), r.head.appendChild(t)));
    }
  }
  function Tf(e, t) {
    _f.m(e, t);
    var n = bf;
    if (n && e) {
      var r = t && typeof t.as == "string" ? t.as : "script", i = "link[rel=\"modulepreload\"][as=\"" + Ht(r) + "\"][href=\"" + Ht(e) + "\"]", a = i;
      switch (r) {
        case "audioworklet":
        case "paintworklet":
        case "serviceworker":
        case "sharedworker":
        case "worker":
        case "script": a = Pf(e);
      }
      if (!mf.has(a) && (e = h({
        rel: "modulepreload",
        href: e
      }, t), mf.set(a, e), n.querySelector(i) === null)) {
        switch (r) {
          case "audioworklet":
          case "paintworklet":
          case "serviceworker":
          case "sharedworker":
          case "worker":
          case "script": if (n.querySelector(Ff(a))) return;
        }
        r = n.createElement("link"), Pd(r, "link", e), wt(r), n.head.appendChild(r);
      }
    }
  }
  function Ef(e, t, n) {
    _f.S(e, t, n);
    var r = bf;
    if (r && e) {
      var i = Ct(r).hoistableStyles, a = Af(e);
      t ||= "default";
      var o = i.get(a);
      if (!o) {
        var s = {
          loading: 0,
          preload: null
        };
        if (o = r.querySelector(jf(a))) s.loading = 5;
        else {
          e = h({
            rel: "stylesheet",
            href: e,
            "data-precedence": t
          }, n), (n = mf.get(a)) && Rf(e, n);
          var c = o = r.createElement("link");
          wt(c), Pd(c, "link", e), c._p = new Promise(function(e, t) {
            c.onload = e, c.onerror = t;
          }), c.addEventListener("load", function() {
            s.loading |= 1;
          }), c.addEventListener("error", function() {
            s.loading |= 2;
          }), s.loading |= 4, Lf(o, t, r);
        }
        o = {
          type: "stylesheet",
          instance: o,
          count: 1,
          state: s
        }, i.set(a, o);
      }
    }
  }
  function Df(e, t) {
    _f.X(e, t);
    var n = bf;
    if (n && e) {
      var r = Ct(n).hoistableScripts, i = Pf(e), a = r.get(i);
      a || (a = n.querySelector(Ff(i)), a || (e = h({
        src: e,
        async: !0
      }, t), (t = mf.get(i)) && zf(e, t), a = n.createElement("script"), wt(a), Pd(a, "link", e), n.head.appendChild(a)), a = {
        type: "script",
        instance: a,
        count: 1,
        state: null
      }, r.set(i, a));
    }
  }
  function Of(e, t) {
    _f.M(e, t);
    var n = bf;
    if (n && e) {
      var r = Ct(n).hoistableScripts, i = Pf(e), a = r.get(i);
      a || (a = n.querySelector(Ff(i)), a || (e = h({
        src: e,
        async: !0,
        type: "module"
      }, t), (t = mf.get(i)) && zf(e, t), a = n.createElement("script"), wt(a), Pd(a, "link", e), n.head.appendChild(a)), a = {
        type: "script",
        instance: a,
        count: 1,
        state: null
      }, r.set(i, a));
    }
  }
  function kf(e, t, n, r) {
    var a = (a = pe.current) ? gf(a) : null;
    if (!a) throw Error(i(446));
    switch (e) {
      case "meta":
      case "title": return null;
      case "style": return typeof n.precedence == "string" && typeof n.href == "string" ? (t = Af(n.href), n = Ct(a).hoistableStyles, r = n.get(t), r || (r = {
        type: "style",
        instance: null,
        count: 0,
        state: null
      }, n.set(t, r)), r) : {
        type: "void",
        instance: null,
        count: 0,
        state: null
      };
      case "link":
        if (n.rel === "stylesheet" && typeof n.href == "string" && typeof n.precedence == "string") {
          e = Af(n.href);
          var o = Ct(a).hoistableStyles, s = o.get(e);
          if (s || (a = a.ownerDocument || a, s = {
            type: "stylesheet",
            instance: null,
            count: 0,
            state: {
              loading: 0,
              preload: null
            }
          }, o.set(e, s), (o = a.querySelector(jf(e))) && !o._p && (s.instance = o, s.state.loading = 5), mf.has(e) || (n = {
            rel: "preload",
            as: "style",
            href: n.href,
            crossOrigin: n.crossOrigin,
            integrity: n.integrity,
            media: n.media,
            hrefLang: n.hrefLang,
            referrerPolicy: n.referrerPolicy
          }, mf.set(e, n), o || Nf(a, e, n, s.state))), t && r === null) throw Error(i(528, ""));
          return s;
        }
        if (t && r !== null) throw Error(i(529, ""));
        return null;
      case "script": return t = n.async, n = n.src, typeof n == "string" && t && typeof t != "function" && typeof t != "symbol" ? (t = Pf(n), n = Ct(a).hoistableScripts, r = n.get(t), r || (r = {
        type: "script",
        instance: null,
        count: 0,
        state: null
      }, n.set(t, r)), r) : {
        type: "void",
        instance: null,
        count: 0,
        state: null
      };
      default: throw Error(i(444, e));
    }
  }
  function Af(e) {
    return "href=\"" + Ht(e) + "\"";
  }
  function jf(e) {
    return "link[rel=\"stylesheet\"][" + e + "]";
  }
  function Mf(e) {
    return h({}, e, {
      "data-precedence": e.precedence,
      precedence: null
    });
  }
  function Nf(e, t, n, r) {
    e.querySelector("link[rel=\"preload\"][as=\"style\"][" + t + "]") ? r.loading = 1 : (t = e.createElement("link"), r.preload = t, t.addEventListener("load", function() {
      return r.loading |= 1;
    }), t.addEventListener("error", function() {
      return r.loading |= 2;
    }), Pd(t, "link", n), wt(t), e.head.appendChild(t));
  }
  function Pf(e) {
    return "[src=\"" + Ht(e) + "\"]";
  }
  function Ff(e) {
    return "script[async]" + e;
  }
  function If(e, t, n) {
    if (t.count++, t.instance === null) switch (t.type) {
      case "style":
        var r = e.querySelector("style[data-href~=\"" + Ht(n.href) + "\"]");
        if (r) return t.instance = r, wt(r), r;
        var a = h({}, n, {
          "data-href": n.href,
          "data-precedence": n.precedence,
          href: null,
          precedence: null
        });
        return r = (e.ownerDocument || e).createElement("style"), wt(r), Pd(r, "style", a), Lf(r, n.precedence, e), t.instance = r;
      case "stylesheet":
        a = Af(n.href);
        var o = e.querySelector(jf(a));
        if (o) return t.state.loading |= 4, t.instance = o, wt(o), o;
        r = Mf(n), (a = mf.get(a)) && Rf(r, a), o = (e.ownerDocument || e).createElement("link"), wt(o);
        var s = o;
        return s._p = new Promise(function(e, t) {
          s.onload = e, s.onerror = t;
        }), Pd(o, "link", r), t.state.loading |= 4, Lf(o, n.precedence, e), t.instance = o;
      case "script": return o = Pf(n.src), (a = e.querySelector(Ff(o))) ? (t.instance = a, wt(a), a) : (r = n, (a = mf.get(o)) && (r = h({}, n), zf(r, a)), e = e.ownerDocument || e, a = e.createElement("script"), wt(a), Pd(a, "link", r), e.head.appendChild(a), t.instance = a);
      case "void": return null;
      default: throw Error(i(443, t.type));
    }
    else t.type === "stylesheet" && !(t.state.loading & 4) && (r = t.instance, t.state.loading |= 4, Lf(r, n.precedence, e));
    return t.instance;
  }
  function Lf(e, t, n) {
    for (var r = n.querySelectorAll("link[rel=\"stylesheet\"][data-precedence],style[data-precedence]"), i = r.length ? r[r.length - 1] : null, a = i, o = 0; o < r.length; o++) {
      var s = r[o];
      if (s.dataset.precedence === t) a = s;
      else if (a !== i) break;
    }
    a ? a.parentNode.insertBefore(e, a.nextSibling) : (t = n.nodeType === 9 ? n.head : n, t.insertBefore(e, t.firstChild));
  }
  function Rf(e, t) {
    e.crossOrigin ??= t.crossOrigin, e.referrerPolicy ??= t.referrerPolicy, e.title ??= t.title;
  }
  function zf(e, t) {
    e.crossOrigin ??= t.crossOrigin, e.referrerPolicy ??= t.referrerPolicy, e.integrity ??= t.integrity;
  }
  var Bf = null;
  function Vf(e, t, n) {
    if (Bf === null) {
      var r = /* @__PURE__ */ new Map(), i = Bf = /* @__PURE__ */ new Map();
      i.set(n, r);
    } else i = Bf, r = i.get(n), r || (r = /* @__PURE__ */ new Map(), i.set(n, r));
    if (r.has(e)) return r;
    for (r.set(e, null), n = n.getElementsByTagName(e), i = 0; i < n.length; i++) {
      var a = n[i];
      if (!(a[vt] || a[dt] || e === "link" && a.getAttribute("rel") === "stylesheet") && a.namespaceURI !== "http://www.w3.org/2000/svg") {
        var o = a.getAttribute(t) || "";
        o = e + o;
        var s = r.get(o);
        s ? s.push(a) : r.set(o, [a]);
      }
    }
    return r;
  }
  function Hf(e, t, n) {
    e = e.ownerDocument || e, e.head.insertBefore(n, t === "title" ? e.querySelector("head > title") : null);
  }
  function Uf(e, t, n) {
    if (n === 1 || t.itemProp != null) return !1;
    switch (e) {
      case "meta":
      case "title": return !0;
      case "style":
        if (typeof t.precedence != "string" || typeof t.href != "string" || t.href === "") break;
        return !0;
      case "link":
        if (typeof t.rel != "string" || typeof t.href != "string" || t.href === "" || t.onLoad || t.onError) break;
        switch (t.rel) {
          case "stylesheet": return e = t.disabled, typeof t.precedence == "string" && e == null;
          default: return !0;
        }
      case "script": if (t.async && typeof t.async != "function" && typeof t.async != "symbol" && !t.onLoad && !t.onError && t.src && typeof t.src == "string") return !0;
    }
    return !1;
  }
  function Wf(e) {
    return !(e.type === "stylesheet" && !(e.state.loading & 3));
  }
  function Gf(e, t, n, r) {
    if (n.type === "stylesheet" && (typeof r.media != "string" || !1 !== matchMedia(r.media).matches) && !(n.state.loading & 4)) {
      if (n.instance === null) {
        var i = Af(r.href), a = t.querySelector(jf(i));
        if (a) {
          t = a._p, typeof t == "object" && t && typeof t.then == "function" && (e.count++, e = Jf.bind(e), t.then(e, e)), n.state.loading |= 4, n.instance = a, wt(a);
          return;
        }
        a = t.ownerDocument || t, r = Mf(r), (i = mf.get(i)) && Rf(r, i), a = a.createElement("link"), wt(a);
        var o = a;
        o._p = new Promise(function(e, t) {
          o.onload = e, o.onerror = t;
        }), Pd(a, "link", r), n.instance = a;
      }
      e.stylesheets === null && (e.stylesheets = /* @__PURE__ */ new Map()), e.stylesheets.set(n, t), (t = n.state.preload) && !(n.state.loading & 3) && (e.count++, n = Jf.bind(e), t.addEventListener("load", n), t.addEventListener("error", n));
    }
  }
  var Kf = 0;
  function qf(e, t) {
    return e.stylesheets && e.count === 0 && Xf(e, e.stylesheets), 0 < e.count || 0 < e.imgCount ? function(n) {
      var r = setTimeout(function() {
        if (e.stylesheets && Xf(e, e.stylesheets), e.unsuspend) {
          var t = e.unsuspend;
          e.unsuspend = null, t();
        }
      }, 6e4 + t);
      0 < e.imgBytes && Kf === 0 && (Kf = 62500 * Ld());
      var i = setTimeout(function() {
        if (e.waitingForImages = !1, e.count === 0 && (e.stylesheets && Xf(e, e.stylesheets), e.unsuspend)) {
          var t = e.unsuspend;
          e.unsuspend = null, t();
        }
      }, (e.imgBytes > Kf ? 50 : 800) + t);
      return e.unsuspend = n, function() {
        e.unsuspend = null, clearTimeout(r), clearTimeout(i);
      };
    } : null;
  }
  function Jf() {
    if (this.count--, this.count === 0 && (this.imgCount === 0 || !this.waitingForImages)) {
      if (this.stylesheets) Xf(this, this.stylesheets);
      else if (this.unsuspend) {
        var e = this.unsuspend;
        this.unsuspend = null, e();
      }
    }
  }
  var Yf = null;
  function Xf(e, t) {
    e.stylesheets = null, e.unsuspend !== null && (e.count++, Yf = /* @__PURE__ */ new Map(), t.forEach(Zf, e), Yf = null, Jf.call(e));
  }
  function Zf(e, t) {
    if (!(t.state.loading & 4)) {
      var n = Yf.get(e);
      if (n) var r = n.get(null);
      else {
        n = /* @__PURE__ */ new Map(), Yf.set(e, n);
        for (var i = e.querySelectorAll("link[data-precedence],style[data-precedence]"), a = 0; a < i.length; a++) {
          var o = i[a];
          (o.nodeName === "LINK" || o.getAttribute("media") !== "not all") && (n.set(o.dataset.precedence, o), r = o);
        }
        r && n.set(null, r);
      }
      i = t.instance, o = i.getAttribute("data-precedence"), a = n.get(o) || r, a === r && n.set(null, i), n.set(o, i), this.count++, r = Jf.bind(this), i.addEventListener("load", r), i.addEventListener("error", r), a ? a.parentNode.insertBefore(i, a.nextSibling) : (e = e.nodeType === 9 ? e.head : e, e.insertBefore(i, e.firstChild)), t.state.loading |= 4;
    }
  }
  var Qf = {
    $$typeof: C,
    Provider: null,
    Consumer: null,
    _currentValue: se,
    _currentValue2: se,
    _threadCount: 0
  };
  function $f(e, t, n, r, i, a, o, s, c) {
    this.tag = 1, this.containerInfo = e, this.pingCache = this.current = this.pendingChildren = null, this.timeoutHandle = -1, this.callbackNode = this.next = this.pendingContext = this.context = this.cancelPendingCommit = null, this.callbackPriority = 0, this.expirationTimes = et(-1), this.entangledLanes = this.shellSuspendCounter = this.errorRecoveryDisabledLanes = this.expiredLanes = this.warmLanes = this.pingedLanes = this.suspendedLanes = this.pendingLanes = 0, this.entanglements = et(0), this.hiddenUpdates = et(null), this.identifierPrefix = r, this.onUncaughtError = i, this.onCaughtError = a, this.onRecoverableError = o, this.pooledCache = null, this.pooledCacheLanes = 0, this.formState = c, this.incompleteTransitions = /* @__PURE__ */ new Map();
  }
  function ep(e, t, n, r, i, a, o, s, c, l, u, d) {
    return e = new $f(e, t, n, o, c, l, u, d, s), t = 1, !0 === a && (t |= 24), a = Qr(3, null, null, t), e.current = a, a.stateNode = e, t = Y(), t.refCount++, e.pooledCache = t, t.refCount++, a.memoizedState = {
      element: r,
      isDehydrated: n,
      cache: t
    }, Aa(a), e;
  }
  function tp(e) {
    return e ? (e = Xr, e) : Xr;
  }
  function np(e, t, n, r, i, a) {
    i = tp(i), r.context === null ? r.context = i : r.pendingContext = i, r = Ma(t), r.payload = { element: n }, a = a === void 0 ? null : a, a !== null && (r.callback = a), n = Na(e, r, t), n !== null && (fu(n, e, t), Pa(n, e, t));
  }
  function rp(e, t) {
    if (e = e.memoizedState, e !== null && e.dehydrated !== null) {
      var n = e.retryLane;
      e.retryLane = n !== 0 && n < t ? n : t;
    }
  }
  function ip(e, t) {
    rp(e, t), (e = e.alternate) && rp(e, t);
  }
  function ap(e) {
    if (e.tag === 13 || e.tag === 31) {
      var t = qr(e, 67108864);
      t !== null && fu(t, e, 67108864), ip(e, 67108864);
    }
  }
  function op(e) {
    if (e.tag === 13 || e.tag === 31) {
      var t = uu();
      t = ot(t);
      var n = qr(e, t);
      n !== null && fu(n, e, t), ip(e, t);
    }
  }
  var sp = !0;
  function cp(e, t, n, r) {
    var i = k.T;
    k.T = null;
    var a = A.p;
    try {
      A.p = 2, up(e, t, n, r);
    } finally {
      A.p = a, k.T = i;
    }
  }
  function lp(e, t, n, r) {
    var i = k.T;
    k.T = null;
    var a = A.p;
    try {
      A.p = 8, up(e, t, n, r);
    } finally {
      A.p = a, k.T = i;
    }
  }
  function up(e, t, n, r) {
    if (sp) {
      var i = dp(r);
      if (i === null) Cd(e, t, r, fp, n), Cp(e, r);
      else if (Tp(i, e, t, n, r)) r.stopPropagation();
      else if (Cp(e, r), t & 4 && -1 < Sp.indexOf(e)) {
        for (; i !== null;) {
          var a = xt(i);
          if (a !== null) switch (a.tag) {
            case 3:
              if (a = a.stateNode, a.current.memoizedState.isDehydrated) {
                var o = Ye(a.pendingLanes);
                if (o !== 0) {
                  var s = a;
                  for (s.pendingLanes |= 2, s.entangledLanes |= 2; o;) {
                    var c = 1 << 31 - He(o);
                    s.entanglements[1] |= c, o &= ~c;
                  }
                  td(a), !(jl & 6) && (Ql = Ae() + 500, nd(0, !1));
                }
              }
              break;
            case 31:
            case 13: s = qr(a, 2), s !== null && fu(s, a, 2), _u(), ip(a, 2);
          }
          if (a = dp(r), a === null && Cd(e, t, r, fp, n), a === i) break;
          i = a;
        }
        i !== null && r.stopPropagation();
      } else Cd(e, t, r, null, n);
    }
  }
  function dp(e) {
    return e = an(e), pp(e);
  }
  var fp = null;
  function pp(e) {
    if (fp = null, e = bt(e), e !== null) {
      var t = o(e);
      if (t === null) e = null;
      else {
        var n = t.tag;
        if (n === 13) {
          if (e = s(t), e !== null) return e;
          e = null;
        } else if (n === 31) {
          if (e = c(t), e !== null) return e;
          e = null;
        } else if (n === 3) {
          if (t.stateNode.current.memoizedState.isDehydrated) return t.tag === 3 ? t.stateNode.containerInfo : null;
          e = null;
        } else t !== e && (e = null);
      }
    }
    return fp = e, null;
  }
  function mp(e) {
    switch (e) {
      case "beforetoggle":
      case "cancel":
      case "click":
      case "close":
      case "contextmenu":
      case "copy":
      case "cut":
      case "auxclick":
      case "dblclick":
      case "dragend":
      case "dragstart":
      case "drop":
      case "focusin":
      case "focusout":
      case "input":
      case "invalid":
      case "keydown":
      case "keypress":
      case "keyup":
      case "mousedown":
      case "mouseup":
      case "paste":
      case "pause":
      case "play":
      case "pointercancel":
      case "pointerdown":
      case "pointerup":
      case "ratechange":
      case "reset":
      case "resize":
      case "seeked":
      case "submit":
      case "toggle":
      case "touchcancel":
      case "touchend":
      case "touchstart":
      case "volumechange":
      case "change":
      case "selectionchange":
      case "textInput":
      case "compositionstart":
      case "compositionend":
      case "compositionupdate":
      case "beforeblur":
      case "afterblur":
      case "beforeinput":
      case "blur":
      case "fullscreenchange":
      case "focus":
      case "hashchange":
      case "popstate":
      case "select":
      case "selectstart": return 2;
      case "drag":
      case "dragenter":
      case "dragexit":
      case "dragleave":
      case "dragover":
      case "mousemove":
      case "mouseout":
      case "mouseover":
      case "pointermove":
      case "pointerout":
      case "pointerover":
      case "scroll":
      case "touchmove":
      case "wheel":
      case "mouseenter":
      case "mouseleave":
      case "pointerenter":
      case "pointerleave": return 8;
      case "message": switch (je()) {
        case Me: return 2;
        case Ne: return 8;
        case Pe:
        case Fe: return 32;
        case Ie: return 268435456;
        default: return 32;
      }
      default: return 32;
    }
  }
  var hp = !1, gp = null, _p = null, vp = null, yp = /* @__PURE__ */ new Map(), bp = /* @__PURE__ */ new Map(), xp = [], Sp = "mousedown mouseup touchcancel touchend touchstart auxclick dblclick pointercancel pointerdown pointerup dragend dragstart drop compositionend compositionstart keydown keypress keyup input textInput copy cut paste click change contextmenu reset".split(" ");
  function Cp(e, t) {
    switch (e) {
      case "focusin":
      case "focusout":
        gp = null;
        break;
      case "dragenter":
      case "dragleave":
        _p = null;
        break;
      case "mouseover":
      case "mouseout":
        vp = null;
        break;
      case "pointerover":
      case "pointerout":
        yp.delete(t.pointerId);
        break;
      case "gotpointercapture":
      case "lostpointercapture": bp.delete(t.pointerId);
    }
  }
  function wp(e, t, n, r, i, a) {
    return e === null || e.nativeEvent !== a ? (e = {
      blockedOn: t,
      domEventName: n,
      eventSystemFlags: r,
      nativeEvent: a,
      targetContainers: [i]
    }, t !== null && (t = xt(t), t !== null && ap(t)), e) : (e.eventSystemFlags |= r, t = e.targetContainers, i !== null && t.indexOf(i) === -1 && t.push(i), e);
  }
  function Tp(e, t, n, r, i) {
    switch (t) {
      case "focusin": return gp = wp(gp, e, t, n, r, i), !0;
      case "dragenter": return _p = wp(_p, e, t, n, r, i), !0;
      case "mouseover": return vp = wp(vp, e, t, n, r, i), !0;
      case "pointerover":
        var a = i.pointerId;
        return yp.set(a, wp(yp.get(a) || null, e, t, n, r, i)), !0;
      case "gotpointercapture": return a = i.pointerId, bp.set(a, wp(bp.get(a) || null, e, t, n, r, i)), !0;
    }
    return !1;
  }
  function Ep(e) {
    var t = bt(e.target);
    if (t !== null) {
      var n = o(t);
      if (n !== null) {
        if (t = n.tag, t === 13) {
          if (t = s(n), t !== null) {
            e.blockedOn = t, lt(e.priority, function() {
              op(n);
            });
            return;
          }
        } else if (t === 31) {
          if (t = c(n), t !== null) {
            e.blockedOn = t, lt(e.priority, function() {
              op(n);
            });
            return;
          }
        } else if (t === 3 && n.stateNode.current.memoizedState.isDehydrated) {
          e.blockedOn = n.tag === 3 ? n.stateNode.containerInfo : null;
          return;
        }
      }
    }
    e.blockedOn = null;
  }
  function Dp(e) {
    if (e.blockedOn !== null) return !1;
    for (var t = e.targetContainers; 0 < t.length;) {
      var n = dp(e.nativeEvent);
      if (n === null) {
        n = e.nativeEvent;
        var r = new n.constructor(n.type, n);
        rn = r, n.target.dispatchEvent(r), rn = null;
      } else return t = xt(n), t !== null && ap(t), e.blockedOn = n, !1;
      t.shift();
    }
    return !0;
  }
  function Op(e, t, n) {
    Dp(e) && n.delete(t);
  }
  function kp() {
    hp = !1, gp !== null && Dp(gp) && (gp = null), _p !== null && Dp(_p) && (_p = null), vp !== null && Dp(vp) && (vp = null), yp.forEach(Op), bp.forEach(Op);
  }
  function Ap(e, n) {
    e.blockedOn === n && (e.blockedOn = null, hp || (hp = !0, t.unstable_scheduleCallback(t.unstable_NormalPriority, kp)));
  }
  var jp = null;
  function Mp(e) {
    jp !== e && (jp = e, t.unstable_scheduleCallback(t.unstable_NormalPriority, function() {
      jp === e && (jp = null);
      for (var t = 0; t < e.length; t += 3) {
        var n = e[t], r = e[t + 1], i = e[t + 2];
        if (typeof r != "function") {
          if (pp(r || n) === null) continue;
          break;
        }
        var a = xt(n);
        a !== null && (e.splice(t, 3), t -= 3, hs(a, {
          pending: !0,
          data: i,
          method: n.method,
          action: r
        }, r, i));
      }
    }));
  }
  function Np(e) {
    function t(t) {
      return Ap(t, e);
    }
    gp !== null && Ap(gp, e), _p !== null && Ap(_p, e), vp !== null && Ap(vp, e), yp.forEach(t), bp.forEach(t);
    for (var n = 0; n < xp.length; n++) {
      var r = xp[n];
      r.blockedOn === e && (r.blockedOn = null);
    }
    for (; 0 < xp.length && (n = xp[0], n.blockedOn === null);) Ep(n), n.blockedOn === null && xp.shift();
    if (n = (e.ownerDocument || e).$$reactFormReplay, n != null) for (r = 0; r < n.length; r += 3) {
      var i = n[r], a = n[r + 1], o = i[ft] || null;
      if (typeof a == "function") o || Mp(n);
      else if (o) {
        var s = null;
        if (a && a.hasAttribute("formAction")) {
          if (i = a, o = a[ft] || null) s = o.formAction;
          else if (pp(i) !== null) continue;
        } else s = o.action;
        typeof s == "function" ? n[r + 1] = s : (n.splice(r, 3), r -= 3), Mp(n);
      }
    }
  }
  function Pp() {
    function e(e) {
      e.canIntercept && e.info === "react-transition" && e.intercept({
        handler: function() {
          return new Promise(function(e) {
            return i = e;
          });
        },
        focusReset: "manual",
        scroll: "manual"
      });
    }
    function t() {
      i !== null && (i(), i = null), r || setTimeout(n, 20);
    }
    function n() {
      if (!r && !navigation.transition) {
        var e = navigation.currentEntry;
        e && e.url != null && navigation.navigate(e.url, {
          state: e.getState(),
          info: "react-transition",
          history: "replace"
        });
      }
    }
    if (typeof navigation == "object") {
      var r = !1, i = null;
      return navigation.addEventListener("navigate", e), navigation.addEventListener("navigatesuccess", t), navigation.addEventListener("navigateerror", t), setTimeout(n, 100), function() {
        r = !0, navigation.removeEventListener("navigate", e), navigation.removeEventListener("navigatesuccess", t), navigation.removeEventListener("navigateerror", t), i !== null && (i(), i = null);
      };
    }
  }
  function Fp(e) {
    this._internalRoot = e;
  }
  Ip.prototype.render = Fp.prototype.render = function(e) {
    var t = this._internalRoot;
    if (t === null) throw Error(i(409));
    var n = t.current;
    np(n, uu(), e, t, null, null);
  }, Ip.prototype.unmount = Fp.prototype.unmount = function() {
    var e = this._internalRoot;
    if (e !== null) {
      this._internalRoot = null;
      var t = e.containerInfo;
      np(e.current, 2, null, e, null, null), _u(), t[pt] = null;
    }
  };
  function Ip(e) {
    this._internalRoot = e;
  }
  Ip.prototype.unstable_scheduleHydration = function(e) {
    if (e) {
      var t = ct();
      e = {
        blockedOn: null,
        target: e,
        priority: t
      };
      for (var n = 0; n < xp.length && t !== 0 && t < xp[n].priority; n++);
      xp.splice(n, 0, e), n === 0 && Ep(e);
    }
  };
  var Lp = n.version;
  if (Lp !== "19.2.7") throw Error(i(527, Lp, "19.2.7"));
  A.findDOMNode = function(e) {
    var t = e._reactInternals;
    if (t === void 0) throw typeof e.render == "function" ? Error(i(188)) : (e = Object.keys(e).join(","), Error(i(268, e)));
    return e = d(t), e = e === null ? null : p(e), e = e === null ? null : e.stateNode, e;
  };
  var Rp = {
    bundleType: 0,
    version: "19.2.7",
    rendererPackageName: "react-dom",
    currentDispatcherRef: k,
    reconcilerVersion: "19.2.7"
  };
  if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ < "u") {
    var zp = __REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (!zp.isDisabled && zp.supportsFiber) try {
      ze = zp.inject(Rp), Be = zp;
    } catch {}
  }
  e.createRoot = function(e, t) {
    if (!a(e)) throw Error(i(299));
    var n = !1, r = "", o = Ls, s = Rs, c = zs;
    return t != null && (!0 === t.unstable_strictMode && (n = !0), t.identifierPrefix !== void 0 && (r = t.identifierPrefix), t.onUncaughtError !== void 0 && (o = t.onUncaughtError), t.onCaughtError !== void 0 && (s = t.onCaughtError), t.onRecoverableError !== void 0 && (c = t.onRecoverableError)), t = ep(e, 1, !1, null, null, n, r, null, o, s, c, Pp), e[pt] = t.current, xd(e), new Fp(t);
  };
})), g = /* @__PURE__ */ o(((e, t) => {
  function n() {
    if (!(typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ > "u" || typeof __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE != "function")) try {
      __REACT_DEVTOOLS_GLOBAL_HOOK__.checkDCE(n);
    } catch (e) {
      console.error(e);
    }
  }
  n(), t.exports = h();
})), _ = (...e) => e.filter((e, t, n) => !!e && e.trim() !== "" && n.indexOf(e) === t).join(" ").trim(), v = (e) => e.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase(), y = (e) => e.replace(/^([A-Z])|[\s-_]+(\w)/g, (e, t, n) => n ? n.toUpperCase() : t.toLowerCase()), b = (e) => {
  let t = y(e);
  return t.charAt(0).toUpperCase() + t.slice(1);
}, x = {
  xmlns: "http://www.w3.org/2000/svg",
  width: 24,
  height: 24,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round",
  strokeLinejoin: "round"
}, S = (e) => {
  for (let t in e) if (t.startsWith("aria-") || t === "role" || t === "title") return !0;
  return !1;
}, C = /* @__PURE__ */ c(u(), 1), w = (0, C.createContext)({}), T = () => (0, C.useContext)(w), E = (0, C.forwardRef)(({ color: e, size: t, strokeWidth: n, absoluteStrokeWidth: r, className: i = "", children: a, iconNode: o, ...s }, c) => {
  let { size: l = 24, strokeWidth: u = 2, absoluteStrokeWidth: d = !1, color: f = "currentColor", className: p = "" } = T() ?? {}, m = r ?? d ? Number(n ?? u) * 24 / Number(t ?? l) : n ?? u;
  return (0, C.createElement)("svg", {
    ref: c,
    ...x,
    width: t ?? l ?? x.width,
    height: t ?? l ?? x.height,
    stroke: e ?? f,
    strokeWidth: m,
    className: _("lucide", p, i),
    ...!a && !S(s) && { "aria-hidden": "true" },
    ...s
  }, [...o.map(([e, t]) => (0, C.createElement)(e, t)), ...Array.isArray(a) ? a : [a]]);
}), D = (e, t) => {
  let n = (0, C.forwardRef)(({ className: n, ...r }, i) => (0, C.createElement)(E, {
    ref: i,
    iconNode: t,
    className: _(`lucide-${v(b(e))}`, `lucide-${e}`, n),
    ...r
  }));
  return n.displayName = b(e), n;
}, O = D("activity", [["path", {
  d: "M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2",
  key: "169zse"
}]]), ee = D("arrow-right", [["path", {
  d: "M5 12h14",
  key: "1ays0h"
}], ["path", {
  d: "m12 5 7 7-7 7",
  key: "xquz4c"
}]]), te = D("bell", [["path", {
  d: "M10.268 21a2 2 0 0 0 3.464 0",
  key: "vwvbt9"
}], ["path", {
  d: "M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326",
  key: "11g9vi"
}]]), ne = D("book-open-check", [
  ["path", {
    d: "M12 21V7",
    key: "gj6g52"
  }],
  ["path", {
    d: "m16 12 2 2 4-4",
    key: "mdajum"
  }],
  ["path", {
    d: "M22 6V4a1 1 0 0 0-1-1h-5a4 4 0 0 0-4 4 4 4 0 0 0-4-4H3a1 1 0 0 0-1 1v13a1 1 0 0 0 1 1h6a3 3 0 0 1 3 3 3 3 0 0 1 3-3h6a1 1 0 0 0 1-1v-1.3",
    key: "8arnkb"
  }]
]), re = D("bot", [
  ["path", {
    d: "M12 8V4H8",
    key: "hb8ula"
  }],
  ["rect", {
    width: "16",
    height: "12",
    x: "4",
    y: "8",
    rx: "2",
    key: "enze0r"
  }],
  ["path", {
    d: "M2 14h2",
    key: "vft8re"
  }],
  ["path", {
    d: "M20 14h2",
    key: "4cs60a"
  }],
  ["path", {
    d: "M15 13v2",
    key: "1xurst"
  }],
  ["path", {
    d: "M9 13v2",
    key: "rq6x2g"
  }]
]), ie = D("boxes", [
  ["path", {
    d: "M2.97 12.92A2 2 0 0 0 2 14.63v3.24a2 2 0 0 0 .97 1.71l3 1.8a2 2 0 0 0 2.06 0L12 19v-5.5l-5-3-4.03 2.42Z",
    key: "lc1i9w"
  }],
  ["path", {
    d: "m7 16.5-4.74-2.85",
    key: "1o9zyk"
  }],
  ["path", {
    d: "m7 16.5 5-3",
    key: "va8pkn"
  }],
  ["path", {
    d: "M7 16.5v5.17",
    key: "jnp8gn"
  }],
  ["path", {
    d: "M12 13.5V19l3.97 2.38a2 2 0 0 0 2.06 0l3-1.8a2 2 0 0 0 .97-1.71v-3.24a2 2 0 0 0-.97-1.71L17 10.5l-5 3Z",
    key: "8zsnat"
  }],
  ["path", {
    d: "m17 16.5-5-3",
    key: "8arw3v"
  }],
  ["path", {
    d: "m17 16.5 4.74-2.85",
    key: "8rfmw"
  }],
  ["path", {
    d: "M17 16.5v5.17",
    key: "k6z78m"
  }],
  ["path", {
    d: "M7.97 4.42A2 2 0 0 0 7 6.13v4.37l5 3 5-3V6.13a2 2 0 0 0-.97-1.71l-3-1.8a2 2 0 0 0-2.06 0l-3 1.8Z",
    key: "1xygjf"
  }],
  ["path", {
    d: "M12 8 7.26 5.15",
    key: "1vbdud"
  }],
  ["path", {
    d: "m12 8 4.74-2.85",
    key: "3rx089"
  }],
  ["path", {
    d: "M12 13.5V8",
    key: "1io7kd"
  }]
]), ae = D("check", [["path", {
  d: "M20 6 9 17l-5-5",
  key: "1gmf2c"
}]]), oe = D("chevron-down", [["path", {
  d: "m6 9 6 6 6-6",
  key: "qrunsl"
}]]), k = D("circle-check", [["circle", {
  cx: "12",
  cy: "12",
  r: "10",
  key: "1mglay"
}], ["path", {
  d: "m9 12 2 2 4-4",
  key: "dzmm74"
}]]), A = D("circle-dollar-sign", [
  ["circle", {
    cx: "12",
    cy: "12",
    r: "10",
    key: "1mglay"
  }],
  ["path", {
    d: "M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8",
    key: "1h4pet"
  }],
  ["path", {
    d: "M12 18V6",
    key: "zqpxq5"
  }]
]), se = D("clipboard-list", [
  ["rect", {
    width: "8",
    height: "4",
    x: "8",
    y: "2",
    rx: "1",
    ry: "1",
    key: "tgr4d6"
  }],
  ["path", {
    d: "M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2",
    key: "116196"
  }],
  ["path", {
    d: "M12 11h4",
    key: "1jrz19"
  }],
  ["path", {
    d: "M12 16h4",
    key: "n85exb"
  }],
  ["path", {
    d: "M8 11h.01",
    key: "1dfujw"
  }],
  ["path", {
    d: "M8 16h.01",
    key: "18s6g9"
  }]
]), ce = D("clock-3", [["circle", {
  cx: "12",
  cy: "12",
  r: "10",
  key: "1mglay"
}], ["path", {
  d: "M12 6v6h4",
  key: "135r8i"
}]]), j = D("file-check-corner", [
  ["path", {
    d: "M10.5 22H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.706.706l3.588 3.588A2.4 2.4 0 0 1 20 8v6",
    key: "g5mvt7"
  }],
  ["path", {
    d: "M14 2v5a1 1 0 0 0 1 1h5",
    key: "wfsgrz"
  }],
  ["path", {
    d: "m14 20 2 2 4-4",
    key: "15kota"
  }]
]), le = D("file-text", [
  ["path", {
    d: "M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z",
    key: "1oefj6"
  }],
  ["path", {
    d: "M14 2v5a1 1 0 0 0 1 1h5",
    key: "wfsgrz"
  }],
  ["path", {
    d: "M10 9H8",
    key: "b1mrlr"
  }],
  ["path", {
    d: "M16 13H8",
    key: "t4e002"
  }],
  ["path", {
    d: "M16 17H8",
    key: "z1uh3a"
  }]
]), ue = D("gauge", [["path", {
  d: "m12 14 4-4",
  key: "9kzdfg"
}], ["path", {
  d: "M3.34 19a10 10 0 1 1 17.32 0",
  key: "19p75a"
}]]), M = D("key-round", [["path", {
  d: "M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z",
  key: "1s6t7t"
}], ["circle", {
  cx: "16.5",
  cy: "7.5",
  r: ".5",
  fill: "currentColor",
  key: "w0ekpg"
}]]), de = D("layout-dashboard", [
  ["rect", {
    width: "7",
    height: "9",
    x: "3",
    y: "3",
    rx: "1",
    key: "10lvy0"
  }],
  ["rect", {
    width: "7",
    height: "5",
    x: "14",
    y: "3",
    rx: "1",
    key: "16une8"
  }],
  ["rect", {
    width: "7",
    height: "9",
    x: "14",
    y: "12",
    rx: "1",
    key: "1hutg5"
  }],
  ["rect", {
    width: "7",
    height: "5",
    x: "3",
    y: "16",
    rx: "1",
    key: "ldoo1y"
  }]
]), fe = D("life-buoy", [
  ["circle", {
    cx: "12",
    cy: "12",
    r: "10",
    key: "1mglay"
  }],
  ["path", {
    d: "m4.93 4.93 4.24 4.24",
    key: "1ymg45"
  }],
  ["path", {
    d: "m14.83 9.17 4.24-4.24",
    key: "1cb5xl"
  }],
  ["path", {
    d: "m14.83 14.83 4.24 4.24",
    key: "q42g0n"
  }],
  ["path", {
    d: "m9.17 14.83-4.24 4.24",
    key: "bqpfvv"
  }],
  ["circle", {
    cx: "12",
    cy: "12",
    r: "4",
    key: "4exip2"
  }]
]), pe = D("list-checks", [
  ["path", {
    d: "M13 5h8",
    key: "a7qcls"
  }],
  ["path", {
    d: "M13 12h8",
    key: "h98zly"
  }],
  ["path", {
    d: "M13 19h8",
    key: "c3s6r1"
  }],
  ["path", {
    d: "m3 17 2 2 4-4",
    key: "1jhpwq"
  }],
  ["path", {
    d: "m3 7 2 2 4-4",
    key: "1obspn"
  }]
]), me = D("lock-keyhole", [
  ["circle", {
    cx: "12",
    cy: "16",
    r: "1",
    key: "1au0dj"
  }],
  ["rect", {
    x: "3",
    y: "10",
    width: "18",
    height: "12",
    rx: "2",
    key: "6s8ecr"
  }],
  ["path", {
    d: "M7 10V7a5 5 0 0 1 10 0v3",
    key: "1pqi11"
  }]
]), he = D("menu", [
  ["path", {
    d: "M4 5h16",
    key: "1tepv9"
  }],
  ["path", {
    d: "M4 12h16",
    key: "1lakjw"
  }],
  ["path", {
    d: "M4 19h16",
    key: "1djgab"
  }]
]), ge = D("network", [
  ["rect", {
    x: "16",
    y: "16",
    width: "6",
    height: "6",
    rx: "1",
    key: "4q2zg0"
  }],
  ["rect", {
    x: "2",
    y: "16",
    width: "6",
    height: "6",
    rx: "1",
    key: "8cvhb9"
  }],
  ["rect", {
    x: "9",
    y: "2",
    width: "6",
    height: "6",
    rx: "1",
    key: "1egb70"
  }],
  ["path", {
    d: "M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3",
    key: "1jsf9p"
  }],
  ["path", {
    d: "M12 12V8",
    key: "2874zd"
  }]
]), _e = D("panel-left-close", [
  ["rect", {
    width: "18",
    height: "18",
    x: "3",
    y: "3",
    rx: "2",
    key: "afitv7"
  }],
  ["path", {
    d: "M9 3v18",
    key: "fh3hqa"
  }],
  ["path", {
    d: "m16 15-3-3 3-3",
    key: "14y99z"
  }]
]), ve = D("panel-left-open", [
  ["rect", {
    width: "18",
    height: "18",
    x: "3",
    y: "3",
    rx: "2",
    key: "afitv7"
  }],
  ["path", {
    d: "M9 3v18",
    key: "fh3hqa"
  }],
  ["path", {
    d: "m14 9 3 3-3 3",
    key: "8010ee"
  }]
]), ye = D("panel-top", [["rect", {
  width: "18",
  height: "18",
  x: "3",
  y: "3",
  rx: "2",
  key: "afitv7"
}], ["path", {
  d: "M3 9h18",
  key: "1pudct"
}]]), be = D("plug-zap", [
  ["path", {
    d: "M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z",
    key: "goz73y"
  }],
  ["path", {
    d: "m2 22 3-3",
    key: "19mgm9"
  }],
  ["path", {
    d: "M7.5 13.5 10 11",
    key: "7xgeeb"
  }],
  ["path", {
    d: "M10.5 16.5 13 14",
    key: "10btkg"
  }],
  ["path", {
    d: "m18 3-4 4h6l-4 4",
    key: "16psg9"
  }]
]), xe = D("radar", [
  ["path", {
    d: "M19.07 4.93A10 10 0 0 0 6.99 3.34",
    key: "z3du51"
  }],
  ["path", {
    d: "M4 6h.01",
    key: "oypzma"
  }],
  ["path", {
    d: "M2.29 9.62A10 10 0 1 0 21.31 8.35",
    key: "qzzz0"
  }],
  ["path", {
    d: "M16.24 7.76A6 6 0 1 0 8.23 16.67",
    key: "1yjesh"
  }],
  ["path", {
    d: "M12 18h.01",
    key: "mhygvu"
  }],
  ["path", {
    d: "M17.99 11.66A6 6 0 0 1 15.77 16.67",
    key: "1u2y91"
  }],
  ["circle", {
    cx: "12",
    cy: "12",
    r: "2",
    key: "1c9p78"
  }],
  ["path", {
    d: "m13.41 10.59 5.66-5.66",
    key: "mhq4k0"
  }]
]), Se = D("radio-tower", [
  ["path", {
    d: "M4.9 16.1C1 12.2 1 5.8 4.9 1.9",
    key: "s0qx1y"
  }],
  ["path", {
    d: "M7.8 4.7a6.14 6.14 0 0 0-.8 7.5",
    key: "1idnkw"
  }],
  ["circle", {
    cx: "12",
    cy: "9",
    r: "2",
    key: "1092wv"
  }],
  ["path", {
    d: "M16.2 4.8c2 2 2.26 5.11.8 7.47",
    key: "ojru2q"
  }],
  ["path", {
    d: "M19.1 1.9a9.96 9.96 0 0 1 0 14.1",
    key: "rhi7fg"
  }],
  ["path", {
    d: "M9.5 18h5",
    key: "mfy3pd"
  }],
  ["path", {
    d: "m8 22 4-11 4 11",
    key: "25yftu"
  }]
]), Ce = D("refresh-cw", [
  ["path", {
    d: "M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8",
    key: "v9h5vc"
  }],
  ["path", {
    d: "M21 3v5h-5",
    key: "1q7to0"
  }],
  ["path", {
    d: "M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16",
    key: "3uifl3"
  }],
  ["path", {
    d: "M8 16H3v5",
    key: "1cv678"
  }]
]), we = D("scan-search", [
  ["path", {
    d: "M3 7V5a2 2 0 0 1 2-2h2",
    key: "aa7l1z"
  }],
  ["path", {
    d: "M17 3h2a2 2 0 0 1 2 2v2",
    key: "4qcy5o"
  }],
  ["path", {
    d: "M21 17v2a2 2 0 0 1-2 2h-2",
    key: "6vwrx8"
  }],
  ["path", {
    d: "M7 21H5a2 2 0 0 1-2-2v-2",
    key: "ioqczr"
  }],
  ["circle", {
    cx: "12",
    cy: "12",
    r: "3",
    key: "1v7zrd"
  }],
  ["path", {
    d: "m16 16-1.9-1.9",
    key: "1dq9hf"
  }]
]), Te = D("server-cog", [
  ["path", {
    d: "m10.852 14.772-.383.923",
    key: "11vil6"
  }],
  ["path", {
    d: "M13.148 14.772a3 3 0 1 0-2.296-5.544l-.383-.923",
    key: "1v3clb"
  }],
  ["path", {
    d: "m13.148 9.228.383-.923",
    key: "t2zzyc"
  }],
  ["path", {
    d: "m13.53 15.696-.382-.924a3 3 0 1 1-2.296-5.544",
    key: "1bxfiv"
  }],
  ["path", {
    d: "m14.772 10.852.923-.383",
    key: "k9m8cz"
  }],
  ["path", {
    d: "m14.772 13.148.923.383",
    key: "1xvhww"
  }],
  ["path", {
    d: "M4.5 10H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-.5",
    key: "tn8das"
  }],
  ["path", {
    d: "M4.5 14H4a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-4a2 2 0 0 0-2-2h-.5",
    key: "1g2pve"
  }],
  ["path", {
    d: "M6 18h.01",
    key: "uhywen"
  }],
  ["path", {
    d: "M6 6h.01",
    key: "1utrut"
  }],
  ["path", {
    d: "m9.228 10.852-.923-.383",
    key: "1wtb30"
  }],
  ["path", {
    d: "m9.228 13.148-.923.383",
    key: "1a830x"
  }]
]), N = D("shield-check", [["path", {
  d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",
  key: "oel41y"
}], ["path", {
  d: "m9 12 2 2 4-4",
  key: "dzmm74"
}]]), Ee = D("shield-half", [["path", {
  d: "M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",
  key: "oel41y"
}], ["path", {
  d: "M12 22V2",
  key: "zs6s6o"
}]]), De = D("siren", [
  ["path", {
    d: "M7 18v-6a5 5 0 1 1 10 0v6",
    key: "pcx96s"
  }],
  ["path", {
    d: "M5 21a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-1a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2z",
    key: "1b4s83"
  }],
  ["path", {
    d: "M21 12h1",
    key: "jtio3y"
  }],
  ["path", {
    d: "M18.5 4.5 18 5",
    key: "g5sp9y"
  }],
  ["path", {
    d: "M2 12h1",
    key: "1uaihz"
  }],
  ["path", {
    d: "M12 2v1",
    key: "11qlp1"
  }],
  ["path", {
    d: "m4.929 4.929.707.707",
    key: "1i51kw"
  }],
  ["path", {
    d: "M12 12v6",
    key: "3ahymv"
  }]
]), Oe = D("square-kanban", [
  ["rect", {
    width: "18",
    height: "18",
    x: "3",
    y: "3",
    rx: "2",
    key: "afitv7"
  }],
  ["path", {
    d: "M8 7v7",
    key: "1x2jlm"
  }],
  ["path", {
    d: "M12 7v4",
    key: "xawao1"
  }],
  ["path", {
    d: "M16 7v9",
    key: "1hp2iy"
  }]
]), ke = D("target", [
  ["circle", {
    cx: "12",
    cy: "12",
    r: "10",
    key: "1mglay"
  }],
  ["circle", {
    cx: "12",
    cy: "12",
    r: "6",
    key: "1vlfrh"
  }],
  ["circle", {
    cx: "12",
    cy: "12",
    r: "2",
    key: "1c9p78"
  }]
]), Ae = D("triangle-alert", [
  ["path", {
    d: "m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3",
    key: "wmoenq"
  }],
  ["path", {
    d: "M12 9v4",
    key: "juzpu7"
  }],
  ["path", {
    d: "M12 17h.01",
    key: "p32p05"
  }]
]), je = D("user-cog", [
  ["path", {
    d: "M10 15H6a4 4 0 0 0-4 4v2",
    key: "1nfge6"
  }],
  ["path", {
    d: "m14.305 16.53.923-.382",
    key: "1itpsq"
  }],
  ["path", {
    d: "m15.228 13.852-.923-.383",
    key: "eplpkm"
  }],
  ["path", {
    d: "m16.852 12.228-.383-.923",
    key: "13v3q0"
  }],
  ["path", {
    d: "m16.852 17.772-.383.924",
    key: "1i8mnm"
  }],
  ["path", {
    d: "m19.148 12.228.383-.923",
    key: "1q8j1v"
  }],
  ["path", {
    d: "m19.53 18.696-.382-.924",
    key: "vk1qj3"
  }],
  ["path", {
    d: "m20.772 13.852.924-.383",
    key: "n880s0"
  }],
  ["path", {
    d: "m20.772 16.148.924.383",
    key: "1g6xey"
  }],
  ["circle", {
    cx: "18",
    cy: "15",
    r: "3",
    key: "gjjjvw"
  }],
  ["circle", {
    cx: "9",
    cy: "7",
    r: "4",
    key: "nufk8"
  }]
]), Me = D("user-round", [["circle", {
  cx: "12",
  cy: "8",
  r: "5",
  key: "1hypcn"
}], ["path", {
  d: "M20 21a8 8 0 0 0-16 0",
  key: "rfgkzh"
}]]), Ne = D("users", [
  ["path", {
    d: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2",
    key: "1yyitq"
  }],
  ["path", {
    d: "M16 3.128a4 4 0 0 1 0 7.744",
    key: "16gr8j"
  }],
  ["path", {
    d: "M22 21v-2a4 4 0 0 0-3-3.87",
    key: "kshegd"
  }],
  ["circle", {
    cx: "9",
    cy: "7",
    r: "4",
    key: "nufk8"
  }]
]), Pe = D("wrench", [["path", {
  d: "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.106-3.105c.32-.322.863-.22.983.218a6 6 0 0 1-8.259 7.057l-7.91 7.91a1 1 0 0 1-2.999-3l7.91-7.91a6 6 0 0 1 7.057-8.259c.438.12.54.662.219.984z",
  key: "1ngwbx"
}]]), Fe = D("x", [["path", {
  d: "M18 6 6 18",
  key: "1bl5f8"
}], ["path", {
  d: "m6 6 12 12",
  key: "d8bk6v"
}]]), Ie = g();
function Le(e) {
  var t, n, r = "";
  if (typeof e == "string" || typeof e == "number") r += e;
  else if (typeof e == "object") if (Array.isArray(e)) {
    var i = e.length;
    for (t = 0; t < i; t++) e[t] && (n = Le(e[t])) && (r && (r += " "), r += n);
  } else for (n in e) e[n] && (r && (r += " "), r += n);
  return r;
}
function Re() {
  for (var e, t, n = 0, r = "", i = arguments.length; n < i; n++) (e = arguments[n]) && (t = Le(e)) && (r && (r += " "), r += t);
  return r;
}
//#endregion
//#region node_modules/.pnpm/tailwind-merge@3.6.0/node_modules/tailwind-merge/dist/bundle-mjs.mjs
var ze = (e, t) => {
  let n = Array(e.length + t.length);
  for (let t = 0; t < e.length; t++) n[t] = e[t];
  for (let r = 0; r < t.length; r++) n[e.length + r] = t[r];
  return n;
}, Be = (e, t) => ({
  classGroupId: e,
  validator: t
}), Ve = (e = /* @__PURE__ */ new Map(), t = null, n) => ({
  nextPart: e,
  validators: t,
  classGroupId: n
}), He = "-", Ue = [], We = "arbitrary..", Ge = (e) => {
  let t = Je(e), { conflictingClassGroups: n, conflictingClassGroupModifiers: r } = e;
  return {
    getClassGroupId: (e) => {
      if (e.startsWith("[") && e.endsWith("]")) return qe(e);
      let n = e.split(He);
      return Ke(n, +(n[0] === "" && n.length > 1), t);
    },
    getConflictingClassGroupIds: (e, t) => {
      if (t) {
        let t = r[e], i = n[e];
        return t ? i ? ze(i, t) : t : i || Ue;
      }
      return n[e] || Ue;
    }
  };
}, Ke = (e, t, n) => {
  if (e.length - t === 0) return n.classGroupId;
  let r = e[t], i = n.nextPart.get(r);
  if (i) {
    let n = Ke(e, t + 1, i);
    if (n) return n;
  }
  let a = n.validators;
  if (a === null) return;
  let o = t === 0 ? e.join(He) : e.slice(t).join(He), s = a.length;
  for (let e = 0; e < s; e++) {
    let t = a[e];
    if (t.validator(o)) return t.classGroupId;
  }
}, qe = (e) => e.slice(1, -1).indexOf(":") === -1 ? void 0 : (() => {
  let t = e.slice(1, -1), n = t.indexOf(":"), r = t.slice(0, n);
  return r ? We + r : void 0;
})(), Je = (e) => {
  let { theme: t, classGroups: n } = e;
  return Ye(n, t);
}, Ye = (e, t) => {
  let n = Ve();
  for (let r in e) {
    let i = e[r];
    Xe(i, n, r, t);
  }
  return n;
}, Xe = (e, t, n, r) => {
  let i = e.length;
  for (let a = 0; a < i; a++) {
    let i = e[a];
    Ze(i, t, n, r);
  }
}, Ze = (e, t, n, r) => {
  if (typeof e == "string") {
    Qe(e, t, n);
    return;
  }
  if (typeof e == "function") {
    $e(e, t, n, r);
    return;
  }
  et(e, t, n, r);
}, Qe = (e, t, n) => {
  let r = e === "" ? t : tt(t, e);
  r.classGroupId = n;
}, $e = (e, t, n, r) => {
  if (nt(e)) {
    Xe(e(r), t, n, r);
    return;
  }
  t.validators === null && (t.validators = []), t.validators.push(Be(n, e));
}, et = (e, t, n, r) => {
  let i = Object.entries(e), a = i.length;
  for (let e = 0; e < a; e++) {
    let [a, o] = i[e];
    Xe(o, tt(t, a), n, r);
  }
}, tt = (e, t) => {
  let n = e, r = t.split(He), i = r.length;
  for (let e = 0; e < i; e++) {
    let t = r[e], i = n.nextPart.get(t);
    i || (i = Ve(), n.nextPart.set(t, i)), n = i;
  }
  return n;
}, nt = (e) => "isThemeGetter" in e && e.isThemeGetter === !0, rt = (e) => {
  if (e < 1) return {
    get: () => void 0,
    set: () => {}
  };
  let t = 0, n = Object.create(null), r = Object.create(null), i = (i, a) => {
    n[i] = a, t++, t > e && (t = 0, r = n, n = Object.create(null));
  };
  return {
    get(e) {
      let t = n[e];
      if (t !== void 0) return t;
      if ((t = r[e]) !== void 0) return i(e, t), t;
    },
    set(e, t) {
      e in n ? n[e] = t : i(e, t);
    }
  };
}, it = "!", at = ":", ot = [], st = (e, t, n, r, i) => ({
  modifiers: e,
  hasImportantModifier: t,
  baseClassName: n,
  maybePostfixModifierPosition: r,
  isExternal: i
}), ct = (e) => {
  let { prefix: t, experimentalParseClassName: n } = e, r = (e) => {
    let t = [], n = 0, r = 0, i = 0, a, o = e.length;
    for (let s = 0; s < o; s++) {
      let o = e[s];
      if (n === 0 && r === 0) {
        if (o === at) {
          t.push(e.slice(i, s)), i = s + 1;
          continue;
        }
        if (o === "/") {
          a = s;
          continue;
        }
      }
      o === "[" ? n++ : o === "]" ? n-- : o === "(" ? r++ : o === ")" && r--;
    }
    let s = t.length === 0 ? e : e.slice(i), c = s, l = !1;
    s.endsWith(it) ? (c = s.slice(0, -1), l = !0) : s.startsWith(it) && (c = s.slice(1), l = !0);
    let u = a && a > i ? a - i : void 0;
    return st(t, l, c, u);
  };
  if (t) {
    let e = t + at, n = r;
    r = (t) => t.startsWith(e) ? n(t.slice(e.length)) : st(ot, !1, t, void 0, !0);
  }
  if (n) {
    let e = r;
    r = (t) => n({
      className: t,
      parseClassName: e
    });
  }
  return r;
}, lt = (e) => {
  let t = /* @__PURE__ */ new Map();
  return e.orderSensitiveModifiers.forEach((e, n) => {
    t.set(e, 1e6 + n);
  }), (e) => {
    let n = [], r = [];
    for (let i = 0; i < e.length; i++) {
      let a = e[i], o = a[0] === "[", s = t.has(a);
      o || s ? (r.length > 0 && (r.sort(), n.push(...r), r = []), n.push(a)) : r.push(a);
    }
    return r.length > 0 && (r.sort(), n.push(...r)), n;
  };
}, ut = (e) => ({
  cache: rt(e.cacheSize),
  parseClassName: ct(e),
  sortModifiers: lt(e),
  postfixLookupClassGroupIds: dt(e),
  ...Ge(e)
}), dt = (e) => {
  let t = Object.create(null), n = e.postfixLookupClassGroups;
  if (n) for (let e = 0; e < n.length; e++) t[n[e]] = !0;
  return t;
}, ft = /\s+/, pt = (e, t) => {
  let { parseClassName: n, getClassGroupId: r, getConflictingClassGroupIds: i, sortModifiers: a, postfixLookupClassGroupIds: o } = t, s = [], c = e.trim().split(ft), l = "";
  for (let e = c.length - 1; e >= 0; --e) {
    let t = c[e], { isExternal: u, modifiers: d, hasImportantModifier: f, baseClassName: p, maybePostfixModifierPosition: m } = n(t);
    if (u) {
      l = t + (l.length > 0 ? " " + l : l);
      continue;
    }
    let h = !!m, g;
    if (h) {
      g = r(p.substring(0, m));
      let e = g && o[g] ? r(p) : void 0;
      e && e !== g && (g = e, h = !1);
    } else g = r(p);
    if (!g) {
      if (!h) {
        l = t + (l.length > 0 ? " " + l : l);
        continue;
      }
      if (g = r(p), !g) {
        l = t + (l.length > 0 ? " " + l : l);
        continue;
      }
      h = !1;
    }
    let _ = d.length === 0 ? "" : d.length === 1 ? d[0] : a(d).join(":"), v = f ? _ + it : _, y = v + g;
    if (s.indexOf(y) > -1) continue;
    s.push(y);
    let b = i(g, h);
    for (let e = 0; e < b.length; ++e) {
      let t = b[e];
      s.push(v + t);
    }
    l = t + (l.length > 0 ? " " + l : l);
  }
  return l;
}, mt = (...e) => {
  let t = 0, n, r, i = "";
  for (; t < e.length;) (n = e[t++]) && (r = ht(n)) && (i && (i += " "), i += r);
  return i;
}, ht = (e) => {
  if (typeof e == "string") return e;
  let t, n = "";
  for (let r = 0; r < e.length; r++) e[r] && (t = ht(e[r])) && (n && (n += " "), n += t);
  return n;
}, gt = (e, ...t) => {
  let n, r, i, a, o = (o) => (n = ut(t.reduce((e, t) => t(e), e())), r = n.cache.get, i = n.cache.set, a = s, s(o)), s = (e) => {
    let t = r(e);
    if (t) return t;
    let a = pt(e, n);
    return i(e, a), a;
  };
  return a = o, (...e) => a(mt(...e));
}, _t = [], vt = (e) => {
  let t = (t) => t[e] || _t;
  return t.isThemeGetter = !0, t;
}, yt = /^\[(?:(\w[\w-]*):)?(.+)\]$/i, bt = /^\((?:(\w[\w-]*):)?(.+)\)$/i, xt = /^\d+(?:\.\d+)?\/\d+(?:\.\d+)?$/, St = /^(\d+(\.\d+)?)?(xs|sm|md|lg|xl)$/, Ct = /\d+(%|px|r?em|[sdl]?v([hwib]|min|max)|pt|pc|in|cm|mm|cap|ch|ex|r?lh|cq(w|h|i|b|min|max))|\b(calc|min|max|clamp)\(.+\)|^0$/, wt = /^(rgba?|hsla?|hwb|(ok)?(lab|lch)|color-mix)\(.+\)$/, Tt = /^(inset_)?-?((\d+)?\.?(\d+)[a-z]+|0)_-?((\d+)?\.?(\d+)[a-z]+|0)/, Et = /^(url|image|image-set|cross-fade|element|(repeating-)?(linear|radial|conic)-gradient)\(.+\)$/, Dt = (e) => xt.test(e), Ot = (e) => !!e && !Number.isNaN(Number(e)), kt = (e) => !!e && Number.isInteger(Number(e)), At = (e) => e.endsWith("%") && Ot(e.slice(0, -1)), jt = (e) => St.test(e), Mt = () => !0, Nt = (e) => Ct.test(e) && !wt.test(e), Pt = () => !1, Ft = (e) => Tt.test(e), It = (e) => Et.test(e), Lt = (e) => !P(e) && !F(e), Rt = (e) => e.startsWith("@container") && (e[10] === "/" && e[11] !== void 0 || e[11] === "s" && e[16] !== void 0 && e.startsWith("-size/", 10) || e[11] === "n" && e[18] !== void 0 && e.startsWith("-normal/", 10)), zt = (e) => en(e, an, Pt), P = (e) => yt.test(e), Bt = (e) => en(e, on, Nt), Vt = (e) => en(e, sn, Ot), Ht = (e) => en(e, ln, Mt), Ut = (e) => en(e, cn, Pt), Wt = (e) => en(e, nn, Pt), Gt = (e) => en(e, rn, It), Kt = (e) => en(e, un, Ft), F = (e) => bt.test(e), qt = (e) => tn(e, on), Jt = (e) => tn(e, cn), Yt = (e) => tn(e, nn), Xt = (e) => tn(e, an), Zt = (e) => tn(e, rn), Qt = (e) => tn(e, un, !0), $t = (e) => tn(e, ln, !0), en = (e, t, n) => {
  let r = yt.exec(e);
  return r ? r[1] ? t(r[1]) : n(r[2]) : !1;
}, tn = (e, t, n = !1) => {
  let r = bt.exec(e);
  return r ? r[1] ? t(r[1]) : n : !1;
}, nn = (e) => e === "position" || e === "percentage", rn = (e) => e === "image" || e === "url", an = (e) => e === "length" || e === "size" || e === "bg-size", on = (e) => e === "length", sn = (e) => e === "number", cn = (e) => e === "family-name", ln = (e) => e === "number" || e === "weight", un = (e) => e === "shadow", dn = /*#__PURE__*/ gt(() => {
  let e = vt("color"), t = vt("font"), n = vt("text"), r = vt("font-weight"), i = vt("tracking"), a = vt("leading"), o = vt("breakpoint"), s = vt("container"), c = vt("spacing"), l = vt("radius"), u = vt("shadow"), d = vt("inset-shadow"), f = vt("text-shadow"), p = vt("drop-shadow"), m = vt("blur"), h = vt("perspective"), g = vt("aspect"), _ = vt("ease"), v = vt("animate"), y = () => [
    "auto",
    "avoid",
    "all",
    "avoid-page",
    "page",
    "left",
    "right",
    "column"
  ], b = () => [
    "center",
    "top",
    "bottom",
    "left",
    "right",
    "top-left",
    "left-top",
    "top-right",
    "right-top",
    "bottom-right",
    "right-bottom",
    "bottom-left",
    "left-bottom"
  ], x = () => [
    ...b(),
    F,
    P
  ], S = () => [
    "auto",
    "hidden",
    "clip",
    "visible",
    "scroll"
  ], C = () => [
    "auto",
    "contain",
    "none"
  ], w = () => [
    F,
    P,
    c
  ], T = () => [
    Dt,
    "full",
    "auto",
    ...w()
  ], E = () => [
    kt,
    "none",
    "subgrid",
    F,
    P
  ], D = () => [
    "auto",
    { span: [
      "full",
      kt,
      F,
      P
    ] },
    kt,
    F,
    P
  ], O = () => [
    kt,
    "auto",
    F,
    P
  ], ee = () => [
    "auto",
    "min",
    "max",
    "fr",
    F,
    P
  ], te = () => [
    "start",
    "end",
    "center",
    "between",
    "around",
    "evenly",
    "stretch",
    "baseline",
    "center-safe",
    "end-safe"
  ], ne = () => [
    "start",
    "end",
    "center",
    "stretch",
    "center-safe",
    "end-safe"
  ], re = () => ["auto", ...w()], ie = () => [
    Dt,
    "auto",
    "full",
    "dvw",
    "dvh",
    "lvw",
    "lvh",
    "svw",
    "svh",
    "min",
    "max",
    "fit",
    ...w()
  ], ae = () => [
    Dt,
    "screen",
    "full",
    "dvw",
    "lvw",
    "svw",
    "min",
    "max",
    "fit",
    ...w()
  ], oe = () => [
    Dt,
    "screen",
    "full",
    "lh",
    "dvh",
    "lvh",
    "svh",
    "min",
    "max",
    "fit",
    ...w()
  ], k = () => [
    e,
    F,
    P
  ], A = () => [
    ...b(),
    Yt,
    Wt,
    { position: [F, P] }
  ], se = () => ["no-repeat", { repeat: [
    "",
    "x",
    "y",
    "space",
    "round"
  ] }], ce = () => [
    "auto",
    "cover",
    "contain",
    Xt,
    zt,
    { size: [F, P] }
  ], j = () => [
    At,
    qt,
    Bt
  ], le = () => [
    "",
    "none",
    "full",
    l,
    F,
    P
  ], ue = () => [
    "",
    Ot,
    qt,
    Bt
  ], M = () => [
    "solid",
    "dashed",
    "dotted",
    "double"
  ], de = () => [
    "normal",
    "multiply",
    "screen",
    "overlay",
    "darken",
    "lighten",
    "color-dodge",
    "color-burn",
    "hard-light",
    "soft-light",
    "difference",
    "exclusion",
    "hue",
    "saturation",
    "color",
    "luminosity"
  ], fe = () => [
    Ot,
    At,
    Yt,
    Wt
  ], pe = () => [
    "",
    "none",
    m,
    F,
    P
  ], me = () => [
    "none",
    Ot,
    F,
    P
  ], he = () => [
    "none",
    Ot,
    F,
    P
  ], ge = () => [
    Ot,
    F,
    P
  ], _e = () => [
    Dt,
    "full",
    ...w()
  ];
  return {
    cacheSize: 500,
    theme: {
      animate: [
        "spin",
        "ping",
        "pulse",
        "bounce"
      ],
      aspect: ["video"],
      blur: [jt],
      breakpoint: [jt],
      color: [Mt],
      container: [jt],
      "drop-shadow": [jt],
      ease: [
        "in",
        "out",
        "in-out"
      ],
      font: [Lt],
      "font-weight": [
        "thin",
        "extralight",
        "light",
        "normal",
        "medium",
        "semibold",
        "bold",
        "extrabold",
        "black"
      ],
      "inset-shadow": [jt],
      leading: [
        "none",
        "tight",
        "snug",
        "normal",
        "relaxed",
        "loose"
      ],
      perspective: [
        "dramatic",
        "near",
        "normal",
        "midrange",
        "distant",
        "none"
      ],
      radius: [jt],
      shadow: [jt],
      spacing: ["px", Ot],
      text: [jt],
      "text-shadow": [jt],
      tracking: [
        "tighter",
        "tight",
        "normal",
        "wide",
        "wider",
        "widest"
      ]
    },
    classGroups: {
      aspect: [{ aspect: [
        "auto",
        "square",
        Dt,
        P,
        F,
        g
      ] }],
      container: ["container"],
      "container-type": [{ "@container": [
        "",
        "normal",
        "size",
        F,
        P
      ] }],
      "container-named": [Rt],
      columns: [{ columns: [
        Ot,
        P,
        F,
        s
      ] }],
      "break-after": [{ "break-after": y() }],
      "break-before": [{ "break-before": y() }],
      "break-inside": [{ "break-inside": [
        "auto",
        "avoid",
        "avoid-page",
        "avoid-column"
      ] }],
      "box-decoration": [{ "box-decoration": ["slice", "clone"] }],
      box: [{ box: ["border", "content"] }],
      display: [
        "block",
        "inline-block",
        "inline",
        "flex",
        "inline-flex",
        "table",
        "inline-table",
        "table-caption",
        "table-cell",
        "table-column",
        "table-column-group",
        "table-footer-group",
        "table-header-group",
        "table-row-group",
        "table-row",
        "flow-root",
        "grid",
        "inline-grid",
        "contents",
        "list-item",
        "hidden"
      ],
      sr: ["sr-only", "not-sr-only"],
      float: [{ float: [
        "right",
        "left",
        "none",
        "start",
        "end"
      ] }],
      clear: [{ clear: [
        "left",
        "right",
        "both",
        "none",
        "start",
        "end"
      ] }],
      isolation: ["isolate", "isolation-auto"],
      "object-fit": [{ object: [
        "contain",
        "cover",
        "fill",
        "none",
        "scale-down"
      ] }],
      "object-position": [{ object: x() }],
      overflow: [{ overflow: S() }],
      "overflow-x": [{ "overflow-x": S() }],
      "overflow-y": [{ "overflow-y": S() }],
      overscroll: [{ overscroll: C() }],
      "overscroll-x": [{ "overscroll-x": C() }],
      "overscroll-y": [{ "overscroll-y": C() }],
      position: [
        "static",
        "fixed",
        "absolute",
        "relative",
        "sticky"
      ],
      inset: [{ inset: T() }],
      "inset-x": [{ "inset-x": T() }],
      "inset-y": [{ "inset-y": T() }],
      start: [{
        "inset-s": T(),
        start: T()
      }],
      end: [{
        "inset-e": T(),
        end: T()
      }],
      "inset-bs": [{ "inset-bs": T() }],
      "inset-be": [{ "inset-be": T() }],
      top: [{ top: T() }],
      right: [{ right: T() }],
      bottom: [{ bottom: T() }],
      left: [{ left: T() }],
      visibility: [
        "visible",
        "invisible",
        "collapse"
      ],
      z: [{ z: [
        kt,
        "auto",
        F,
        P
      ] }],
      basis: [{ basis: [
        Dt,
        "full",
        "auto",
        s,
        ...w()
      ] }],
      "flex-direction": [{ flex: [
        "row",
        "row-reverse",
        "col",
        "col-reverse"
      ] }],
      "flex-wrap": [{ flex: [
        "nowrap",
        "wrap",
        "wrap-reverse"
      ] }],
      flex: [{ flex: [
        Ot,
        Dt,
        "auto",
        "initial",
        "none",
        P
      ] }],
      grow: [{ grow: [
        "",
        Ot,
        F,
        P
      ] }],
      shrink: [{ shrink: [
        "",
        Ot,
        F,
        P
      ] }],
      order: [{ order: [
        kt,
        "first",
        "last",
        "none",
        F,
        P
      ] }],
      "grid-cols": [{ "grid-cols": E() }],
      "col-start-end": [{ col: D() }],
      "col-start": [{ "col-start": O() }],
      "col-end": [{ "col-end": O() }],
      "grid-rows": [{ "grid-rows": E() }],
      "row-start-end": [{ row: D() }],
      "row-start": [{ "row-start": O() }],
      "row-end": [{ "row-end": O() }],
      "grid-flow": [{ "grid-flow": [
        "row",
        "col",
        "dense",
        "row-dense",
        "col-dense"
      ] }],
      "auto-cols": [{ "auto-cols": ee() }],
      "auto-rows": [{ "auto-rows": ee() }],
      gap: [{ gap: w() }],
      "gap-x": [{ "gap-x": w() }],
      "gap-y": [{ "gap-y": w() }],
      "justify-content": [{ justify: [...te(), "normal"] }],
      "justify-items": [{ "justify-items": [...ne(), "normal"] }],
      "justify-self": [{ "justify-self": ["auto", ...ne()] }],
      "align-content": [{ content: ["normal", ...te()] }],
      "align-items": [{ items: [...ne(), { baseline: ["", "last"] }] }],
      "align-self": [{ self: [
        "auto",
        ...ne(),
        { baseline: ["", "last"] }
      ] }],
      "place-content": [{ "place-content": te() }],
      "place-items": [{ "place-items": [...ne(), "baseline"] }],
      "place-self": [{ "place-self": ["auto", ...ne()] }],
      p: [{ p: w() }],
      px: [{ px: w() }],
      py: [{ py: w() }],
      ps: [{ ps: w() }],
      pe: [{ pe: w() }],
      pbs: [{ pbs: w() }],
      pbe: [{ pbe: w() }],
      pt: [{ pt: w() }],
      pr: [{ pr: w() }],
      pb: [{ pb: w() }],
      pl: [{ pl: w() }],
      m: [{ m: re() }],
      mx: [{ mx: re() }],
      my: [{ my: re() }],
      ms: [{ ms: re() }],
      me: [{ me: re() }],
      mbs: [{ mbs: re() }],
      mbe: [{ mbe: re() }],
      mt: [{ mt: re() }],
      mr: [{ mr: re() }],
      mb: [{ mb: re() }],
      ml: [{ ml: re() }],
      "space-x": [{ "space-x": w() }],
      "space-x-reverse": ["space-x-reverse"],
      "space-y": [{ "space-y": w() }],
      "space-y-reverse": ["space-y-reverse"],
      size: [{ size: ie() }],
      "inline-size": [{ inline: ["auto", ...ae()] }],
      "min-inline-size": [{ "min-inline": ["auto", ...ae()] }],
      "max-inline-size": [{ "max-inline": ["none", ...ae()] }],
      "block-size": [{ block: ["auto", ...oe()] }],
      "min-block-size": [{ "min-block": ["auto", ...oe()] }],
      "max-block-size": [{ "max-block": ["none", ...oe()] }],
      w: [{ w: [
        s,
        "screen",
        ...ie()
      ] }],
      "min-w": [{ "min-w": [
        s,
        "screen",
        "none",
        ...ie()
      ] }],
      "max-w": [{ "max-w": [
        s,
        "screen",
        "none",
        "prose",
        { screen: [o] },
        ...ie()
      ] }],
      h: [{ h: [
        "screen",
        "lh",
        ...ie()
      ] }],
      "min-h": [{ "min-h": [
        "screen",
        "lh",
        "none",
        ...ie()
      ] }],
      "max-h": [{ "max-h": [
        "screen",
        "lh",
        ...ie()
      ] }],
      "font-size": [{ text: [
        "base",
        n,
        qt,
        Bt
      ] }],
      "font-smoothing": ["antialiased", "subpixel-antialiased"],
      "font-style": ["italic", "not-italic"],
      "font-weight": [{ font: [
        r,
        $t,
        Ht
      ] }],
      "font-stretch": [{ "font-stretch": [
        "ultra-condensed",
        "extra-condensed",
        "condensed",
        "semi-condensed",
        "normal",
        "semi-expanded",
        "expanded",
        "extra-expanded",
        "ultra-expanded",
        At,
        P
      ] }],
      "font-family": [{ font: [
        Jt,
        Ut,
        t
      ] }],
      "font-features": [{ "font-features": [P] }],
      "fvn-normal": ["normal-nums"],
      "fvn-ordinal": ["ordinal"],
      "fvn-slashed-zero": ["slashed-zero"],
      "fvn-figure": ["lining-nums", "oldstyle-nums"],
      "fvn-spacing": ["proportional-nums", "tabular-nums"],
      "fvn-fraction": ["diagonal-fractions", "stacked-fractions"],
      tracking: [{ tracking: [
        i,
        F,
        P
      ] }],
      "line-clamp": [{ "line-clamp": [
        Ot,
        "none",
        F,
        Vt
      ] }],
      leading: [{ leading: [a, ...w()] }],
      "list-image": [{ "list-image": [
        "none",
        F,
        P
      ] }],
      "list-style-position": [{ list: ["inside", "outside"] }],
      "list-style-type": [{ list: [
        "disc",
        "decimal",
        "none",
        F,
        P
      ] }],
      "text-alignment": [{ text: [
        "left",
        "center",
        "right",
        "justify",
        "start",
        "end"
      ] }],
      "placeholder-color": [{ placeholder: k() }],
      "text-color": [{ text: k() }],
      "text-decoration": [
        "underline",
        "overline",
        "line-through",
        "no-underline"
      ],
      "text-decoration-style": [{ decoration: [...M(), "wavy"] }],
      "text-decoration-thickness": [{ decoration: [
        Ot,
        "from-font",
        "auto",
        F,
        Bt
      ] }],
      "text-decoration-color": [{ decoration: k() }],
      "underline-offset": [{ "underline-offset": [
        Ot,
        "auto",
        F,
        P
      ] }],
      "text-transform": [
        "uppercase",
        "lowercase",
        "capitalize",
        "normal-case"
      ],
      "text-overflow": [
        "truncate",
        "text-ellipsis",
        "text-clip"
      ],
      "text-wrap": [{ text: [
        "wrap",
        "nowrap",
        "balance",
        "pretty"
      ] }],
      indent: [{ indent: w() }],
      "tab-size": [{ tab: [
        kt,
        F,
        P
      ] }],
      "vertical-align": [{ align: [
        "baseline",
        "top",
        "middle",
        "bottom",
        "text-top",
        "text-bottom",
        "sub",
        "super",
        F,
        P
      ] }],
      whitespace: [{ whitespace: [
        "normal",
        "nowrap",
        "pre",
        "pre-line",
        "pre-wrap",
        "break-spaces"
      ] }],
      break: [{ break: [
        "normal",
        "words",
        "all",
        "keep"
      ] }],
      wrap: [{ wrap: [
        "break-word",
        "anywhere",
        "normal"
      ] }],
      hyphens: [{ hyphens: [
        "none",
        "manual",
        "auto"
      ] }],
      content: [{ content: [
        "none",
        F,
        P
      ] }],
      "bg-attachment": [{ bg: [
        "fixed",
        "local",
        "scroll"
      ] }],
      "bg-clip": [{ "bg-clip": [
        "border",
        "padding",
        "content",
        "text"
      ] }],
      "bg-origin": [{ "bg-origin": [
        "border",
        "padding",
        "content"
      ] }],
      "bg-position": [{ bg: A() }],
      "bg-repeat": [{ bg: se() }],
      "bg-size": [{ bg: ce() }],
      "bg-image": [{ bg: [
        "none",
        {
          linear: [
            { to: [
              "t",
              "tr",
              "r",
              "br",
              "b",
              "bl",
              "l",
              "tl"
            ] },
            kt,
            F,
            P
          ],
          radial: [
            "",
            F,
            P
          ],
          conic: [
            kt,
            F,
            P
          ]
        },
        Zt,
        Gt
      ] }],
      "bg-color": [{ bg: k() }],
      "gradient-from-pos": [{ from: j() }],
      "gradient-via-pos": [{ via: j() }],
      "gradient-to-pos": [{ to: j() }],
      "gradient-from": [{ from: k() }],
      "gradient-via": [{ via: k() }],
      "gradient-to": [{ to: k() }],
      rounded: [{ rounded: le() }],
      "rounded-s": [{ "rounded-s": le() }],
      "rounded-e": [{ "rounded-e": le() }],
      "rounded-t": [{ "rounded-t": le() }],
      "rounded-r": [{ "rounded-r": le() }],
      "rounded-b": [{ "rounded-b": le() }],
      "rounded-l": [{ "rounded-l": le() }],
      "rounded-ss": [{ "rounded-ss": le() }],
      "rounded-se": [{ "rounded-se": le() }],
      "rounded-ee": [{ "rounded-ee": le() }],
      "rounded-es": [{ "rounded-es": le() }],
      "rounded-tl": [{ "rounded-tl": le() }],
      "rounded-tr": [{ "rounded-tr": le() }],
      "rounded-br": [{ "rounded-br": le() }],
      "rounded-bl": [{ "rounded-bl": le() }],
      "border-w": [{ border: ue() }],
      "border-w-x": [{ "border-x": ue() }],
      "border-w-y": [{ "border-y": ue() }],
      "border-w-s": [{ "border-s": ue() }],
      "border-w-e": [{ "border-e": ue() }],
      "border-w-bs": [{ "border-bs": ue() }],
      "border-w-be": [{ "border-be": ue() }],
      "border-w-t": [{ "border-t": ue() }],
      "border-w-r": [{ "border-r": ue() }],
      "border-w-b": [{ "border-b": ue() }],
      "border-w-l": [{ "border-l": ue() }],
      "divide-x": [{ "divide-x": ue() }],
      "divide-x-reverse": ["divide-x-reverse"],
      "divide-y": [{ "divide-y": ue() }],
      "divide-y-reverse": ["divide-y-reverse"],
      "border-style": [{ border: [
        ...M(),
        "hidden",
        "none"
      ] }],
      "divide-style": [{ divide: [
        ...M(),
        "hidden",
        "none"
      ] }],
      "border-color": [{ border: k() }],
      "border-color-x": [{ "border-x": k() }],
      "border-color-y": [{ "border-y": k() }],
      "border-color-s": [{ "border-s": k() }],
      "border-color-e": [{ "border-e": k() }],
      "border-color-bs": [{ "border-bs": k() }],
      "border-color-be": [{ "border-be": k() }],
      "border-color-t": [{ "border-t": k() }],
      "border-color-r": [{ "border-r": k() }],
      "border-color-b": [{ "border-b": k() }],
      "border-color-l": [{ "border-l": k() }],
      "divide-color": [{ divide: k() }],
      "outline-style": [{ outline: [
        ...M(),
        "none",
        "hidden"
      ] }],
      "outline-offset": [{ "outline-offset": [
        Ot,
        F,
        P
      ] }],
      "outline-w": [{ outline: [
        "",
        Ot,
        qt,
        Bt
      ] }],
      "outline-color": [{ outline: k() }],
      shadow: [{ shadow: [
        "",
        "none",
        u,
        Qt,
        Kt
      ] }],
      "shadow-color": [{ shadow: k() }],
      "inset-shadow": [{ "inset-shadow": [
        "none",
        d,
        Qt,
        Kt
      ] }],
      "inset-shadow-color": [{ "inset-shadow": k() }],
      "ring-w": [{ ring: ue() }],
      "ring-w-inset": ["ring-inset"],
      "ring-color": [{ ring: k() }],
      "ring-offset-w": [{ "ring-offset": [Ot, Bt] }],
      "ring-offset-color": [{ "ring-offset": k() }],
      "inset-ring-w": [{ "inset-ring": ue() }],
      "inset-ring-color": [{ "inset-ring": k() }],
      "text-shadow": [{ "text-shadow": [
        "none",
        f,
        Qt,
        Kt
      ] }],
      "text-shadow-color": [{ "text-shadow": k() }],
      opacity: [{ opacity: [
        Ot,
        F,
        P
      ] }],
      "mix-blend": [{ "mix-blend": [
        ...de(),
        "plus-darker",
        "plus-lighter"
      ] }],
      "bg-blend": [{ "bg-blend": de() }],
      "mask-clip": [{ "mask-clip": [
        "border",
        "padding",
        "content",
        "fill",
        "stroke",
        "view"
      ] }, "mask-no-clip"],
      "mask-composite": [{ mask: [
        "add",
        "subtract",
        "intersect",
        "exclude"
      ] }],
      "mask-image-linear-pos": [{ "mask-linear": [Ot] }],
      "mask-image-linear-from-pos": [{ "mask-linear-from": fe() }],
      "mask-image-linear-to-pos": [{ "mask-linear-to": fe() }],
      "mask-image-linear-from-color": [{ "mask-linear-from": k() }],
      "mask-image-linear-to-color": [{ "mask-linear-to": k() }],
      "mask-image-t-from-pos": [{ "mask-t-from": fe() }],
      "mask-image-t-to-pos": [{ "mask-t-to": fe() }],
      "mask-image-t-from-color": [{ "mask-t-from": k() }],
      "mask-image-t-to-color": [{ "mask-t-to": k() }],
      "mask-image-r-from-pos": [{ "mask-r-from": fe() }],
      "mask-image-r-to-pos": [{ "mask-r-to": fe() }],
      "mask-image-r-from-color": [{ "mask-r-from": k() }],
      "mask-image-r-to-color": [{ "mask-r-to": k() }],
      "mask-image-b-from-pos": [{ "mask-b-from": fe() }],
      "mask-image-b-to-pos": [{ "mask-b-to": fe() }],
      "mask-image-b-from-color": [{ "mask-b-from": k() }],
      "mask-image-b-to-color": [{ "mask-b-to": k() }],
      "mask-image-l-from-pos": [{ "mask-l-from": fe() }],
      "mask-image-l-to-pos": [{ "mask-l-to": fe() }],
      "mask-image-l-from-color": [{ "mask-l-from": k() }],
      "mask-image-l-to-color": [{ "mask-l-to": k() }],
      "mask-image-x-from-pos": [{ "mask-x-from": fe() }],
      "mask-image-x-to-pos": [{ "mask-x-to": fe() }],
      "mask-image-x-from-color": [{ "mask-x-from": k() }],
      "mask-image-x-to-color": [{ "mask-x-to": k() }],
      "mask-image-y-from-pos": [{ "mask-y-from": fe() }],
      "mask-image-y-to-pos": [{ "mask-y-to": fe() }],
      "mask-image-y-from-color": [{ "mask-y-from": k() }],
      "mask-image-y-to-color": [{ "mask-y-to": k() }],
      "mask-image-radial": [{ "mask-radial": [F, P] }],
      "mask-image-radial-from-pos": [{ "mask-radial-from": fe() }],
      "mask-image-radial-to-pos": [{ "mask-radial-to": fe() }],
      "mask-image-radial-from-color": [{ "mask-radial-from": k() }],
      "mask-image-radial-to-color": [{ "mask-radial-to": k() }],
      "mask-image-radial-shape": [{ "mask-radial": ["circle", "ellipse"] }],
      "mask-image-radial-size": [{ "mask-radial": [{
        closest: ["side", "corner"],
        farthest: ["side", "corner"]
      }] }],
      "mask-image-radial-pos": [{ "mask-radial-at": b() }],
      "mask-image-conic-pos": [{ "mask-conic": [Ot] }],
      "mask-image-conic-from-pos": [{ "mask-conic-from": fe() }],
      "mask-image-conic-to-pos": [{ "mask-conic-to": fe() }],
      "mask-image-conic-from-color": [{ "mask-conic-from": k() }],
      "mask-image-conic-to-color": [{ "mask-conic-to": k() }],
      "mask-mode": [{ mask: [
        "alpha",
        "luminance",
        "match"
      ] }],
      "mask-origin": [{ "mask-origin": [
        "border",
        "padding",
        "content",
        "fill",
        "stroke",
        "view"
      ] }],
      "mask-position": [{ mask: A() }],
      "mask-repeat": [{ mask: se() }],
      "mask-size": [{ mask: ce() }],
      "mask-type": [{ "mask-type": ["alpha", "luminance"] }],
      "mask-image": [{ mask: [
        "none",
        F,
        P
      ] }],
      filter: [{ filter: [
        "",
        "none",
        F,
        P
      ] }],
      blur: [{ blur: pe() }],
      brightness: [{ brightness: [
        Ot,
        F,
        P
      ] }],
      contrast: [{ contrast: [
        Ot,
        F,
        P
      ] }],
      "drop-shadow": [{ "drop-shadow": [
        "",
        "none",
        p,
        Qt,
        Kt
      ] }],
      "drop-shadow-color": [{ "drop-shadow": k() }],
      grayscale: [{ grayscale: [
        "",
        Ot,
        F,
        P
      ] }],
      "hue-rotate": [{ "hue-rotate": [
        Ot,
        F,
        P
      ] }],
      invert: [{ invert: [
        "",
        Ot,
        F,
        P
      ] }],
      saturate: [{ saturate: [
        Ot,
        F,
        P
      ] }],
      sepia: [{ sepia: [
        "",
        Ot,
        F,
        P
      ] }],
      "backdrop-filter": [{ "backdrop-filter": [
        "",
        "none",
        F,
        P
      ] }],
      "backdrop-blur": [{ "backdrop-blur": pe() }],
      "backdrop-brightness": [{ "backdrop-brightness": [
        Ot,
        F,
        P
      ] }],
      "backdrop-contrast": [{ "backdrop-contrast": [
        Ot,
        F,
        P
      ] }],
      "backdrop-grayscale": [{ "backdrop-grayscale": [
        "",
        Ot,
        F,
        P
      ] }],
      "backdrop-hue-rotate": [{ "backdrop-hue-rotate": [
        Ot,
        F,
        P
      ] }],
      "backdrop-invert": [{ "backdrop-invert": [
        "",
        Ot,
        F,
        P
      ] }],
      "backdrop-opacity": [{ "backdrop-opacity": [
        Ot,
        F,
        P
      ] }],
      "backdrop-saturate": [{ "backdrop-saturate": [
        Ot,
        F,
        P
      ] }],
      "backdrop-sepia": [{ "backdrop-sepia": [
        "",
        Ot,
        F,
        P
      ] }],
      "border-collapse": [{ border: ["collapse", "separate"] }],
      "border-spacing": [{ "border-spacing": w() }],
      "border-spacing-x": [{ "border-spacing-x": w() }],
      "border-spacing-y": [{ "border-spacing-y": w() }],
      "table-layout": [{ table: ["auto", "fixed"] }],
      caption: [{ caption: ["top", "bottom"] }],
      transition: [{ transition: [
        "",
        "all",
        "colors",
        "opacity",
        "shadow",
        "transform",
        "none",
        F,
        P
      ] }],
      "transition-behavior": [{ transition: ["normal", "discrete"] }],
      duration: [{ duration: [
        Ot,
        "initial",
        F,
        P
      ] }],
      ease: [{ ease: [
        "linear",
        "initial",
        _,
        F,
        P
      ] }],
      delay: [{ delay: [
        Ot,
        F,
        P
      ] }],
      animate: [{ animate: [
        "none",
        v,
        F,
        P
      ] }],
      backface: [{ backface: ["hidden", "visible"] }],
      perspective: [{ perspective: [
        h,
        F,
        P
      ] }],
      "perspective-origin": [{ "perspective-origin": x() }],
      rotate: [{ rotate: me() }],
      "rotate-x": [{ "rotate-x": me() }],
      "rotate-y": [{ "rotate-y": me() }],
      "rotate-z": [{ "rotate-z": me() }],
      scale: [{ scale: he() }],
      "scale-x": [{ "scale-x": he() }],
      "scale-y": [{ "scale-y": he() }],
      "scale-z": [{ "scale-z": he() }],
      "scale-3d": ["scale-3d"],
      skew: [{ skew: ge() }],
      "skew-x": [{ "skew-x": ge() }],
      "skew-y": [{ "skew-y": ge() }],
      transform: [{ transform: [
        F,
        P,
        "",
        "none",
        "gpu",
        "cpu"
      ] }],
      "transform-origin": [{ origin: x() }],
      "transform-style": [{ transform: ["3d", "flat"] }],
      translate: [{ translate: _e() }],
      "translate-x": [{ "translate-x": _e() }],
      "translate-y": [{ "translate-y": _e() }],
      "translate-z": [{ "translate-z": _e() }],
      "translate-none": ["translate-none"],
      zoom: [{ zoom: [
        kt,
        F,
        P
      ] }],
      accent: [{ accent: k() }],
      appearance: [{ appearance: ["none", "auto"] }],
      "caret-color": [{ caret: k() }],
      "color-scheme": [{ scheme: [
        "normal",
        "dark",
        "light",
        "light-dark",
        "only-dark",
        "only-light"
      ] }],
      cursor: [{ cursor: [
        "auto",
        "default",
        "pointer",
        "wait",
        "text",
        "move",
        "help",
        "not-allowed",
        "none",
        "context-menu",
        "progress",
        "cell",
        "crosshair",
        "vertical-text",
        "alias",
        "copy",
        "no-drop",
        "grab",
        "grabbing",
        "all-scroll",
        "col-resize",
        "row-resize",
        "n-resize",
        "e-resize",
        "s-resize",
        "w-resize",
        "ne-resize",
        "nw-resize",
        "se-resize",
        "sw-resize",
        "ew-resize",
        "ns-resize",
        "nesw-resize",
        "nwse-resize",
        "zoom-in",
        "zoom-out",
        F,
        P
      ] }],
      "field-sizing": [{ "field-sizing": ["fixed", "content"] }],
      "pointer-events": [{ "pointer-events": ["auto", "none"] }],
      resize: [{ resize: [
        "none",
        "",
        "y",
        "x"
      ] }],
      "scroll-behavior": [{ scroll: ["auto", "smooth"] }],
      "scrollbar-thumb-color": [{ "scrollbar-thumb": k() }],
      "scrollbar-track-color": [{ "scrollbar-track": k() }],
      "scrollbar-gutter": [{ "scrollbar-gutter": [
        "auto",
        "stable",
        "both"
      ] }],
      "scrollbar-w": [{ scrollbar: [
        "auto",
        "thin",
        "none"
      ] }],
      "scroll-m": [{ "scroll-m": w() }],
      "scroll-mx": [{ "scroll-mx": w() }],
      "scroll-my": [{ "scroll-my": w() }],
      "scroll-ms": [{ "scroll-ms": w() }],
      "scroll-me": [{ "scroll-me": w() }],
      "scroll-mbs": [{ "scroll-mbs": w() }],
      "scroll-mbe": [{ "scroll-mbe": w() }],
      "scroll-mt": [{ "scroll-mt": w() }],
      "scroll-mr": [{ "scroll-mr": w() }],
      "scroll-mb": [{ "scroll-mb": w() }],
      "scroll-ml": [{ "scroll-ml": w() }],
      "scroll-p": [{ "scroll-p": w() }],
      "scroll-px": [{ "scroll-px": w() }],
      "scroll-py": [{ "scroll-py": w() }],
      "scroll-ps": [{ "scroll-ps": w() }],
      "scroll-pe": [{ "scroll-pe": w() }],
      "scroll-pbs": [{ "scroll-pbs": w() }],
      "scroll-pbe": [{ "scroll-pbe": w() }],
      "scroll-pt": [{ "scroll-pt": w() }],
      "scroll-pr": [{ "scroll-pr": w() }],
      "scroll-pb": [{ "scroll-pb": w() }],
      "scroll-pl": [{ "scroll-pl": w() }],
      "snap-align": [{ snap: [
        "start",
        "end",
        "center",
        "align-none"
      ] }],
      "snap-stop": [{ snap: ["normal", "always"] }],
      "snap-type": [{ snap: [
        "none",
        "x",
        "y",
        "both"
      ] }],
      "snap-strictness": [{ snap: ["mandatory", "proximity"] }],
      touch: [{ touch: [
        "auto",
        "none",
        "manipulation"
      ] }],
      "touch-x": [{ "touch-pan": [
        "x",
        "left",
        "right"
      ] }],
      "touch-y": [{ "touch-pan": [
        "y",
        "up",
        "down"
      ] }],
      "touch-pz": ["touch-pinch-zoom"],
      select: [{ select: [
        "none",
        "text",
        "all",
        "auto"
      ] }],
      "will-change": [{ "will-change": [
        "auto",
        "scroll",
        "contents",
        "transform",
        F,
        P
      ] }],
      fill: [{ fill: ["none", ...k()] }],
      "stroke-w": [{ stroke: [
        Ot,
        qt,
        Bt,
        Vt
      ] }],
      stroke: [{ stroke: ["none", ...k()] }],
      "forced-color-adjust": [{ "forced-color-adjust": ["auto", "none"] }]
    },
    conflictingClassGroups: {
      "container-named": ["container-type"],
      overflow: ["overflow-x", "overflow-y"],
      overscroll: ["overscroll-x", "overscroll-y"],
      inset: [
        "inset-x",
        "inset-y",
        "inset-bs",
        "inset-be",
        "start",
        "end",
        "top",
        "right",
        "bottom",
        "left"
      ],
      "inset-x": ["right", "left"],
      "inset-y": ["top", "bottom"],
      flex: [
        "basis",
        "grow",
        "shrink"
      ],
      gap: ["gap-x", "gap-y"],
      p: [
        "px",
        "py",
        "ps",
        "pe",
        "pbs",
        "pbe",
        "pt",
        "pr",
        "pb",
        "pl"
      ],
      px: ["pr", "pl"],
      py: ["pt", "pb"],
      m: [
        "mx",
        "my",
        "ms",
        "me",
        "mbs",
        "mbe",
        "mt",
        "mr",
        "mb",
        "ml"
      ],
      mx: ["mr", "ml"],
      my: ["mt", "mb"],
      size: ["w", "h"],
      "font-size": ["leading"],
      "fvn-normal": [
        "fvn-ordinal",
        "fvn-slashed-zero",
        "fvn-figure",
        "fvn-spacing",
        "fvn-fraction"
      ],
      "fvn-ordinal": ["fvn-normal"],
      "fvn-slashed-zero": ["fvn-normal"],
      "fvn-figure": ["fvn-normal"],
      "fvn-spacing": ["fvn-normal"],
      "fvn-fraction": ["fvn-normal"],
      "line-clamp": ["display", "overflow"],
      rounded: [
        "rounded-s",
        "rounded-e",
        "rounded-t",
        "rounded-r",
        "rounded-b",
        "rounded-l",
        "rounded-ss",
        "rounded-se",
        "rounded-ee",
        "rounded-es",
        "rounded-tl",
        "rounded-tr",
        "rounded-br",
        "rounded-bl"
      ],
      "rounded-s": ["rounded-ss", "rounded-es"],
      "rounded-e": ["rounded-se", "rounded-ee"],
      "rounded-t": ["rounded-tl", "rounded-tr"],
      "rounded-r": ["rounded-tr", "rounded-br"],
      "rounded-b": ["rounded-br", "rounded-bl"],
      "rounded-l": ["rounded-tl", "rounded-bl"],
      "border-spacing": ["border-spacing-x", "border-spacing-y"],
      "border-w": [
        "border-w-x",
        "border-w-y",
        "border-w-s",
        "border-w-e",
        "border-w-bs",
        "border-w-be",
        "border-w-t",
        "border-w-r",
        "border-w-b",
        "border-w-l"
      ],
      "border-w-x": ["border-w-r", "border-w-l"],
      "border-w-y": ["border-w-t", "border-w-b"],
      "border-color": [
        "border-color-x",
        "border-color-y",
        "border-color-s",
        "border-color-e",
        "border-color-bs",
        "border-color-be",
        "border-color-t",
        "border-color-r",
        "border-color-b",
        "border-color-l"
      ],
      "border-color-x": ["border-color-r", "border-color-l"],
      "border-color-y": ["border-color-t", "border-color-b"],
      translate: [
        "translate-x",
        "translate-y",
        "translate-none"
      ],
      "translate-none": [
        "translate",
        "translate-x",
        "translate-y",
        "translate-z"
      ],
      "scroll-m": [
        "scroll-mx",
        "scroll-my",
        "scroll-ms",
        "scroll-me",
        "scroll-mbs",
        "scroll-mbe",
        "scroll-mt",
        "scroll-mr",
        "scroll-mb",
        "scroll-ml"
      ],
      "scroll-mx": ["scroll-mr", "scroll-ml"],
      "scroll-my": ["scroll-mt", "scroll-mb"],
      "scroll-p": [
        "scroll-px",
        "scroll-py",
        "scroll-ps",
        "scroll-pe",
        "scroll-pbs",
        "scroll-pbe",
        "scroll-pt",
        "scroll-pr",
        "scroll-pb",
        "scroll-pl"
      ],
      "scroll-px": ["scroll-pr", "scroll-pl"],
      "scroll-py": ["scroll-pt", "scroll-pb"],
      touch: [
        "touch-x",
        "touch-y",
        "touch-pz"
      ],
      "touch-x": ["touch"],
      "touch-y": ["touch"],
      "touch-pz": ["touch"]
    },
    conflictingClassGroupModifiers: { "font-size": ["leading"] },
    postfixLookupClassGroups: ["container-type"],
    orderSensitiveModifiers: [
      "*",
      "**",
      "after",
      "backdrop",
      "before",
      "details-content",
      "file",
      "first-letter",
      "first-line",
      "marker",
      "placeholder",
      "selection"
    ]
  };
});
//#endregion
//#region apps/web/react/src/lib/utils.ts
function fn(...e) {
  return dn(Re(e));
}
function pn(e, t = "0") {
  return typeof e != "number" || !Number.isFinite(e) ? t : new Intl.NumberFormat("en-US").format(e);
}
function I(e) {
  if (!e) return "Not recorded";
  let t = new Date(String(e));
  return Number.isNaN(t.getTime()) ? String(e) : t.toLocaleString(void 0, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
}
function mn(e) {
  return Array.isArray(e) ? e : e && typeof e == "object" && Array.isArray(e.items) ? e.items : [];
}
function hn(e) {
  return e >= 80 ? "success" : e >= 55 ? "warn" : "danger";
}
function gn(e, t = 0, n = 100) {
  return Math.min(n, Math.max(t, e));
}
var _n = {
  must_block_before_origin: "Must be blocked before origin",
  must_allow_baseline_health: "Must allow baseline health",
  must_challenge_or_rate_limit: "Must challenge or rate-limit",
  must_not_expose_direct_ip: "Must not expose direct IP"
};
function vn(e) {
  return _n[e] ?? e.replace(/_/g, " ");
}
//#endregion
//#region apps/web/react/src/lib/api.ts
var yn = "astranull.portal.session.v1";
function bn(e) {
  return e.authMode === "oidc-jwt";
}
function xn(e) {
  let t = e.trim();
  return /^https?:\/\//i.test(t);
}
function Sn(e) {
  let t = e.replace(/\/+$/, "") || "/";
  return t === "/internal/admin" || t.startsWith("/internal/admin/") || t === "/internal/soc" || t.startsWith("/internal/soc/") ? "staff" : "customer";
}
function Cn(e, t = "customer") {
  if (!bn(e) || e.bundledLoginEnabled) return null;
  let n = t === "staff" ? e.staffLoginPath : e.loginUrl;
  return xn(n) ? n : null;
}
function wn(e) {
  let t = Number(e.expires_in ?? 3600);
  return {
    mode: "oidc",
    access_token: String(e.access_token ?? ""),
    principal: String(e.principal ?? "customer"),
    tenant_id: e.tenant_id == null ? void 0 : String(e.tenant_id),
    user_id: e.user_id == null ? void 0 : String(e.user_id),
    role: e.role == null ? void 0 : String(e.role),
    staff_id: e.staff_id == null ? void 0 : String(e.staff_id),
    staff_role: e.staff_role == null ? void 0 : String(e.staff_role),
    expires_at: Date.now() + t * 1e3
  };
}
function Tn() {
  try {
    let e = sessionStorage.getItem(yn);
    if (!e) return null;
    let t = JSON.parse(e);
    return !t || typeof t != "object" ? null : t.expires_at && Date.now() > Number(t.expires_at) ? (sessionStorage.removeItem(yn), null) : t;
  } catch {
    return null;
  }
}
function En(e) {
  sessionStorage.setItem(yn, JSON.stringify(e));
}
function Dn() {
  sessionStorage.removeItem(yn);
}
function On(e) {
  return e ? JSON.stringify({
    tenant_id: e.tenant_id ?? "",
    user_id: e.user_id ?? "",
    principal: e.principal ?? "",
    staff_id: e.staff_id ?? "",
    role: e.role ?? "",
    staff_role: e.staff_role ?? ""
  }) : "";
}
async function kn() {
  let [e, t] = await Promise.all([fetch("/ready").catch(() => null), fetch("/v1/public/site-config").catch(() => null)]), n = e?.ok ? await e.json().catch(() => ({})) : {}, r = t?.ok ? await t.json().catch(() => ({})) : {};
  return {
    authMode: String(n.auth_mode ?? r.auth_mode ?? "dev-headers"),
    siteConfig: r,
    bundledLoginEnabled: r.bundled_staging_login_enabled === !0,
    loginUrl: String(r.login_url ?? "/login"),
    portalPath: String(r.customer_portal_path ?? "/app"),
    staffLoginPath: "/internal/admin/login"
  };
}
async function An(e = "customer") {
  let t = await kn(), n = Tn();
  if (t.authMode === "dev-headers") {
    if (!n) {
      let n = e === "staff" ? {
        mode: "dev-headers",
        principal: "staff",
        staff_id: "staff_admin",
        staff_role: "internal_admin"
      } : {
        mode: "dev-headers",
        principal: "customer",
        tenant_id: "ten_demo",
        user_id: "usr_admin",
        role: "admin"
      };
      return En(n), {
        config: t,
        session: n,
        redirectToLogin: !1
      };
    }
    return {
      config: t,
      session: n,
      redirectToLogin: !1
    };
  }
  let r = e === "staff" ? n?.staff_login_path ?? t.staffLoginPath : t.loginUrl, i = !!String(n?.access_token ?? "").trim(), a = e === "staff" ? n?.principal === "staff" : n?.principal !== "staff";
  if (!i || !a) {
    let n = Cn(t, e);
    return n ? {
      config: t,
      session: null,
      redirectToLogin: !0,
      loginUrl: n
    } : t.bundledLoginEnabled ? {
      config: t,
      session: null,
      redirectToLogin: !0,
      loginUrl: r
    } : {
      config: t,
      session: null,
      redirectToLogin: !0,
      loginUrl: r,
      errorMessage: "Sign in is required. Configure enterprise SSO or enable bundled staging login for this environment."
    };
  }
  return {
    config: t,
    session: n,
    redirectToLogin: !1
  };
}
var jn = /* @__PURE__ */ new Set(["soc_analyst", "soc_lead"]);
function Mn(e) {
  return jn.has(String(e.staff_role ?? "").trim().toLowerCase());
}
function Nn(e, t) {
  let n = {
    "Content-Type": "application/json",
    accept: "application/json"
  };
  if (e.authMode === "dev-headers") return t.principal === "staff" ? (n["x-principal-type"] = "staff", n["x-staff-id"] = String(t.staff_id ?? t.user_id ?? "staff_dev"), n["x-staff-role"] = String(t.staff_role ?? t.role ?? "support_engineer"), n) : (n["x-tenant-id"] = String(t.tenant_id ?? "ten_demo"), n["x-user-id"] = String(t.user_id ?? "usr_admin"), n["x-role"] = String(t.role ?? "admin"), n);
  let r = String(t.access_token ?? "").trim();
  return r && (n.authorization = `Bearer ${r}`), n;
}
function Pn(e, t, n = "ten_demo") {
  let r = Nn(e, t);
  return e.authMode === "dev-headers" && (delete r["x-principal-type"], delete r["x-staff-id"], delete r["x-staff-role"], r["x-tenant-id"] = n, r["x-user-id"] = String(t.staff_id ?? t.user_id ?? "staff_soc"), r["x-role"] = "soc"), r;
}
async function Fn(e, t) {
  let n = await fetch(e, { headers: t });
  if (!n.ok) throw Error(`${e} returned ${n.status}`);
  return n.json();
}
async function In(e, t, n = {}) {
  let r = await fetch(e, {
    method: n.method ?? "GET",
    headers: t,
    body: n.body === void 0 ? void 0 : JSON.stringify(n.body)
  }), i = await r.json().catch(() => null);
  if (!r.ok) {
    let t = i && typeof i == "object" && "message" in i ? String(i.message) : `${e} returned ${r.status}`, n = Error(t);
    throw n.status = r.status, n.payload = i, n;
  }
  return i;
}
async function L(e, t, n, r = {}) {
  return In(n, Nn(e, t), r);
}
async function Ln(e, t, n, r = {}) {
  return In(n, Pn(e, t, r.tenantId), r);
}
async function Rn(e, t, n) {
  try {
    return await Fn(e, t);
  } catch {
    return n;
  }
}
function zn(e) {
  return !e || typeof e != "object" || Array.isArray(e) ? null : e;
}
async function Bn(e, t, n = {}) {
  let r = Nn(e, t), i = t.principal === "staff", a = i && Mn(t) && n.route === "internal-soc" ? Pn(e, t) : r, o = await Rn("/v1/tenant/deployment-features", r, null), s = typeof o == "object" && !!o && o.connectors === !0, c = typeof o == "object" && !!o && o.waf_posture === !0, l = typeof o == "object" && !!o && o.external_discovery === !0, [u, d, f, p, m, h, g, _, v, y, b, x, S, C, w, T, E, D, O, ee, te, ne, re, ie, ae, oe, k, A, se, ce, j, le, ue, M, de, fe, pe, me, he, ge] = await Promise.all([
    Rn("/v1/state", a, null),
    Rn("/v1/tenants/current", r, null),
    Rn("/v1/target-groups", r, { items: [] }),
    Rn("/v1/agents", r, { items: [] }),
    Rn("/v1/checks", r, { items: [] }),
    Rn("/v1/test-policies", r, { items: [] }),
    Rn("/v1/test-runs", r, { items: [] }),
    Rn("/v1/findings", a, { items: [] }),
    Rn("/v1/evidence", r, { items: [] }),
    Rn("/v1/high-scale-requests", a, { items: [] }),
    Rn("/v1/reports", r, { items: [] }),
    Rn("/v1/notifications", r, {
      rules: [],
      events: []
    }),
    Rn("/v1/production-release-evidence", r, { items: [] }),
    Rn("/v1/production-release-evidence/attestation", r, null),
    Rn("/v1/audit-log", r, { items: [] }),
    s ? Rn("/v1/connectors", r, { items: [] }) : Promise.resolve({ items: [] }),
    Rn("/v1/secrets", r, { items: [] }),
    Rn("/v1/bootstrap-tokens", r, { items: [] }),
    Rn("/v1/service-accounts", r, { items: [] }),
    c ? Rn("/v1/waf/assets", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/coverage", r, null) : Promise.resolve(null),
    c ? Rn("/v1/waf/coverage/risk-roadmap", r, null) : Promise.resolve(null),
    c ? Rn("/v1/waf/validations", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/drift-events", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/exceptions", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/validation-plans", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/retests", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/action-items", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/cve-pipeline", r, { items: [] }) : Promise.resolve({ items: [] }),
    c ? Rn("/v1/waf/supply-chain/risks", r, { items: [] }) : Promise.resolve({ items: [] }),
    l ? Rn("/v1/discovery/entities", r, { items: [] }) : Promise.resolve({ items: [] }),
    l ? Rn("/v1/discovery/candidates", r, { items: [] }) : Promise.resolve({ items: [] }),
    l ? Rn("/v1/discovery/inbox", r, { items: [] }) : Promise.resolve({ items: [] }),
    l ? Rn("/v1/discovery/reports/summary", r, null) : Promise.resolve(null),
    i ? Promise.resolve(null) : Rn("/v1/subscription/current", r, null),
    i ? Rn("/internal/admin/overview", r, null) : Promise.resolve(null),
    i ? Rn("/internal/admin/signup-requests", r, { items: [] }) : Promise.resolve({ items: [] }),
    i ? Rn("/internal/admin/tenants", r, { items: [] }) : Promise.resolve({ items: [] }),
    i ? Rn("/internal/admin/approval-requests", r, { items: [] }) : Promise.resolve({ items: [] }),
    i ? Rn("/internal/admin/audit-log?limit=20", r, { items: [] }) : Promise.resolve({ items: [] })
  ]);
  return {
    state: u,
    tenant: zn(d),
    targetGroups: mn(f),
    agents: mn(p),
    checks: mn(m),
    testPolicies: mn(h),
    runs: mn(g),
    findings: mn(_),
    evidence: mn(v),
    highScale: mn(y),
    reports: mn(b),
    notificationRules: Array.isArray(x?.rules) ? x.rules : [],
    notificationEvents: Array.isArray(x?.events) ? x.events : [],
    releaseEvidence: mn(S),
    releaseAttestation: zn(C?.attestation ?? C),
    audit: mn(w),
    connectors: mn(T),
    secrets: mn(E),
    bootstrapTokens: mn(D),
    serviceAccounts: mn(O),
    wafAssets: mn(ee),
    wafCoverage: zn(te),
    wafRiskRoadmap: zn(ne),
    wafValidations: mn(re),
    wafDriftEvents: mn(ie),
    wafExceptions: mn(ae),
    wafValidationPlans: mn(oe),
    wafRetests: mn(k),
    wafActionItems: mn(A),
    cvePipeline: mn(se),
    supplyChainRisks: mn(ce),
    discoveryEntities: mn(j),
    discoveryCandidates: mn(le),
    discoveryInbox: mn(ue),
    discoverySummary: zn(M),
    subscriptionSummary: zn(de),
    internalOverview: zn(fe),
    internalSignupRequests: mn(pe),
    internalTenants: mn(me),
    internalApprovalRequests: mn(he),
    internalAudit: mn(ge),
    deploymentFeatures: o,
    loaded: !0,
    error: null
  };
}
var Vn = {
  state: null,
  tenant: null,
  targetGroups: [],
  agents: [],
  checks: [],
  testPolicies: [],
  runs: [],
  findings: [],
  evidence: [],
  highScale: [],
  reports: [],
  notificationRules: [],
  notificationEvents: [],
  releaseEvidence: [],
  releaseAttestation: null,
  audit: [],
  connectors: [],
  secrets: [],
  bootstrapTokens: [],
  serviceAccounts: [],
  wafAssets: [],
  wafCoverage: null,
  wafRiskRoadmap: null,
  wafValidations: [],
  wafDriftEvents: [],
  wafExceptions: [],
  wafValidationPlans: [],
  wafRetests: [],
  wafActionItems: [],
  cvePipeline: [],
  supplyChainRisks: [],
  discoveryEntities: [],
  discoveryCandidates: [],
  discoveryInbox: [],
  discoverySummary: null,
  subscriptionSummary: null,
  internalOverview: null,
  internalSignupRequests: [],
  internalTenants: [],
  internalApprovalRequests: [],
  internalAudit: [],
  deploymentFeatures: null,
  loaded: !1,
  error: null
}, Hn = {
  overview: "Overview",
  scope: "Declared scope",
  validation: "Validation",
  posture: "Posture",
  governance: "Governance",
  staff: "Staff"
}, Un = [
  {
    id: "dashboard",
    label: "Dashboard",
    group: "overview",
    description: "Readiness score, coverage, vectors, findings, and SOC status.",
    icon: de
  },
  {
    id: "onboarding",
    label: "Onboarding",
    group: "overview",
    description: "Guided environment, target group, agent, safe run, and evidence setup.",
    icon: ne
  },
  {
    id: "environments",
    label: "Environments",
    group: "scope",
    description: "Declared environment IDs with validation evidence, findings, and active scope counts.",
    icon: Te
  },
  {
    id: "target-groups",
    label: "Target Groups",
    group: "scope",
    description: "Customer-declared business services, expected behavior, and owners.",
    icon: ke
  },
  {
    id: "target-group-detail",
    label: "Target Group Detail",
    group: "scope",
    description: "Per-service tabs for targets, expected behavior, agents, checks, runs, findings, and settings.",
    icon: ye
  },
  {
    id: "agents",
    label: "Agents",
    group: "scope",
    description: "Outbound-only observation agents, placement, versions, and health.",
    icon: re
  },
  {
    id: "agent-detail",
    label: "Agent Detail",
    group: "scope",
    description: "Identity, heartbeat, capabilities, placement evidence, logs, and update history for one outbound agent.",
    icon: re
  },
  {
    id: "checks",
    label: "Checks",
    group: "validation",
    description: "Safe-by-default readiness checks and SOC-gated high-scale scenarios.",
    icon: pe
  },
  {
    id: "test-policies",
    label: "Test Policies",
    group: "validation",
    description: "Cadence, expected verdicts, target bindings, safe windows, and high-scale policy gating.",
    icon: se
  },
  {
    id: "runs",
    label: "Test Runs",
    group: "validation",
    description: "Execution timeline, probe results, agent observations, and verdicts.",
    icon: O
  },
  {
    id: "run-detail",
    label: "Run Detail",
    group: "validation",
    description: "Timeline, probe result, agent observation, correlation truth table, and evidence chain for one run.",
    icon: O
  },
  {
    id: "findings",
    label: "Findings",
    group: "validation",
    description: "Evidence-backed gaps, owners, SLAs, and remediation status.",
    icon: Ae
  },
  {
    id: "evidence",
    label: "Evidence Vault",
    group: "validation",
    description: "Custody-ready evidence, exports, and verdict source material.",
    icon: j
  },
  {
    id: "waf-posture",
    label: "WAF Posture",
    group: "posture",
    description: "Declared WAF assets, coverage rollups, drift visibility, and create actions backed by live APIs.",
    icon: Ee
  },
  {
    id: "waf-asset-detail",
    label: "WAF Asset Detail",
    group: "posture",
    description: "Ruleset effectiveness, bypass classes, drift, exceptions, validation runs, and remediation for one asset.",
    icon: Ee
  },
  {
    id: "cve-pipeline",
    label: "CVE Pipeline",
    group: "posture",
    description: "Live-exposure triage and mitigation workflow for declared assets.",
    icon: xe
  },
  {
    id: "cve-detail",
    label: "CVE Detail",
    group: "posture",
    description: "Triage factors, asset matches, and safe validation actions for one CVE item.",
    icon: xe
  },
  {
    id: "supply-chain",
    label: "Supply Chain",
    group: "posture",
    description: "CNAME, dependency, vendor, and exposure risk tracking.",
    icon: ie
  },
  {
    id: "supply-chain-detail",
    label: "Supply Chain Detail",
    group: "posture",
    description: "Evidence summary, remediation steps, and state actions for one supply-chain risk.",
    icon: ie
  },
  {
    id: "remediation",
    label: "Remediation",
    group: "posture",
    description: "Action items, safe retests, SIEM/SOAR previews, and closure paths.",
    icon: Pe
  },
  {
    id: "discovery",
    label: "Discovery",
    group: "posture",
    description: "Approval-gated candidate inbox that never promotes inventory automatically.",
    icon: we
  },
  {
    id: "discovery-entity",
    label: "Discovery Entity",
    group: "posture",
    description: "Candidate source evidence, confidence, decision trail, promote and dismiss workflow.",
    icon: ge
  },
  {
    id: "high-scale",
    label: "High-Scale Requests",
    group: "governance",
    description: "Customer request form, authorization pack, windows, and custody.",
    icon: De
  },
  {
    id: "soc",
    label: "SOC Console",
    group: "governance",
    description: "SOC-gated queue, kill switch state, checklists, and execution notes.",
    icon: N
  },
  {
    id: "reports",
    label: "Reports",
    group: "governance",
    description: "Executive, technical, SOC, audit, release, and WAF report builders.",
    icon: le
  },
  {
    id: "report-detail",
    label: "Report Detail",
    group: "governance",
    description: "Report kind, custody preview, export formats, and digest verification for one generated report.",
    icon: le
  },
  {
    id: "integrations",
    label: "Integrations",
    group: "governance",
    description: "Notification, ticketing, SIEM, SOAR, and optional read-only provider connectors.",
    icon: be
  },
  {
    id: "notifications",
    label: "Notifications",
    group: "governance",
    description: "Safe in-app rules, provider status, retries, and DLQ recovery.",
    icon: te
  },
  {
    id: "audit",
    label: "Audit Log",
    group: "governance",
    description: "Tenant actions, security-relevant changes, and custody chain records.",
    icon: se
  },
  {
    id: "release-evidence",
    label: "Release Evidence",
    group: "governance",
    description: "Production-readiness evidence inventory and launch gate visibility.",
    icon: Oe
  },
  {
    id: "settings",
    label: "Settings",
    group: "governance",
    description: "Tenant profile, roles, tokens, retention, SSO, and safe defaults.",
    icon: M
  },
  {
    id: "support",
    label: "Support",
    group: "governance",
    description: "Support readiness, escalation paths, runbook references, and non-production on-call posture.",
    icon: fe
  },
  {
    id: "subscription",
    label: "Subscription",
    group: "governance",
    description: "Plan, entitlements, limits, billing state, contract references, and effective dates.",
    icon: A
  },
  {
    id: "admin",
    label: "Admin Console",
    group: "staff",
    description: "Internal overview for sign-ups, tenant lifecycle, approvals, support, and internal audit.",
    icon: je
  },
  {
    id: "tenant-detail",
    label: "Tenant Detail",
    group: "staff",
    description: "Tenant lifecycle, users, entitlements, notes, support actions, subscriptions, and audit activity.",
    icon: je
  },
  {
    id: "internal-soc",
    label: "Internal SOC",
    group: "staff",
    description: "Dedicated staff SOC execution plane with kill switch, Go/No-Go checklist, provider contacts, and timeline.",
    icon: ue
  }
], Wn = new Map(Un.map((e) => [e.id, e]));
function Gn(e) {
  let t = e.replace(/^#/, ""), n = t.includes("?") ? t.slice(0, t.indexOf("?")) : t;
  return Wn.has(n) ? n : null;
}
function Kn() {
  let e = Gn(window.location.hash);
  if (e) return e;
  let t = window.location.pathname.replace(/^\/+/, "").replace(/\/+$/, "");
  if (window.location.pathname === "/internal/admin") return "admin";
  if (window.location.pathname === "/internal/soc" || t === "internal-soc.html") return "internal-soc";
  if (t === "index.html") return "dashboard";
  let n = t.endsWith(".html") ? t.slice(0, -5) : t;
  return Wn.has(n) ? n : Wn.has(t) ? t : "dashboard";
}
var qn = "AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.", Jn = [
  {
    title: "No-access-first",
    body: "Core workflows start from customer-declared targets and do not require cloud credentials."
  },
  {
    title: "Outbound-only agents",
    body: "Agents call AstraNull over outbound HTTPS; no inbound management ports are required."
  },
  {
    title: "SOC-gated high-scale",
    body: "Customers request high-scale validation; SOC approves, schedules, coordinates, stops, and closes."
  },
  {
    title: "Evidence over assumptions",
    body: "Every verdict links back to observed probe data, agent observations, health signals, approvals, or declarations."
  }
], Yn = {
  "target_group:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "target_group:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "bootstrap_token:create": [
    "owner",
    "admin",
    "engineer"
  ],
  "bootstrap_token:read": [
    "owner",
    "admin",
    "engineer",
    "auditor"
  ],
  "bootstrap_token:revoke": ["owner", "admin"],
  "service_account:create": ["owner", "admin"],
  "service_account:read": [
    "owner",
    "admin",
    "auditor"
  ],
  "service_account:revoke": ["owner", "admin"],
  "service_account:rotate": ["owner", "admin"],
  "secret:read": [
    "owner",
    "admin",
    "auditor"
  ],
  "secret:write": ["owner", "admin"],
  "secret:rotate": ["owner", "admin"],
  "agent:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "agent:revoke": ["owner", "admin"],
  "test_policy:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "test_policy:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "test_run:start": [
    "owner",
    "admin",
    "engineer"
  ],
  "test_run:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "finding:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "finding:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "report:create": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor"
  ],
  "audit:read": [
    "owner",
    "admin",
    "soc",
    "auditor"
  ],
  "high_scale:request": [
    "owner",
    "admin",
    "engineer"
  ],
  "high_scale:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "high_scale:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "soc:high_scale": ["soc"],
  "soc:kill_switch": ["soc"],
  "tenant:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "tenant:write": ["owner", "admin"],
  "environment:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "environment:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "evidence:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "evidence:write": [
    "owner",
    "admin",
    "soc"
  ],
  "release_evidence:read": [
    "owner",
    "admin",
    "soc",
    "auditor"
  ],
  "release_evidence:write": [
    "owner",
    "admin",
    "soc"
  ],
  "event:ingest": [
    "owner",
    "admin",
    "engineer",
    "soc"
  ],
  "notification:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor"
  ],
  "notification:write": ["owner", "admin"],
  "agent_update:read": [
    "owner",
    "admin",
    "engineer",
    "auditor"
  ],
  "agent_update:write": ["owner", "admin"],
  "agent_update:rollback": ["owner", "admin"],
  "waf:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "waf:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "waf:run": [
    "owner",
    "admin",
    "engineer"
  ],
  "waf:connector_read": [
    "owner",
    "admin",
    "engineer",
    "auditor"
  ],
  "waf:connector_write": ["owner", "admin"],
  "waf:recommendation_review": [
    "owner",
    "admin",
    "engineer"
  ],
  "waf_offensive:request": [
    "owner",
    "admin",
    "engineer"
  ],
  "waf_offensive:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "waf_offensive:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "soc:waf_offensive": ["soc"],
  "discovery:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "discovery:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "discovery:approve": ["owner", "admin"],
  "cve_pipeline:read": [
    "owner",
    "admin",
    "engineer",
    "soc",
    "auditor",
    "viewer"
  ],
  "cve_pipeline:write": [
    "owner",
    "admin",
    "engineer"
  ],
  "supply_chain:authorize": ["owner", "admin"]
};
function Xn(e, t) {
  let n = Yn[t];
  return n ? n.includes(e) : !1;
}
//#endregion
//#region apps/web/react/src/lib/route-access.mjs
var Zn = /* @__PURE__ */ new Set(["soc_analyst", "soc_lead"]), Qn = Object.freeze({
  notifications: "notification:read",
  audit: "audit:read",
  "release-evidence": "release_evidence:read"
}), $n = /* @__PURE__ */ new Set(["admin", "tenant-detail"]), er = /* @__PURE__ */ new Set(["internal-soc"]);
function tr(e, t, n = {}) {
  let r = String(e ?? "").trim().toLowerCase(), i = String(n.principal ?? "customer").trim().toLowerCase(), a = String(n.staffRole ?? "").trim().toLowerCase();
  if ($n.has(t)) return i === "staff";
  if (er.has(t)) return i === "staff" && Zn.has(a);
  if (t === "soc" && i === "staff") return !1;
  let o = Qn[t];
  return o ? Xn(r, o) : !0;
}
//#endregion
//#region node_modules/.pnpm/class-variance-authority@0.7.1/node_modules/class-variance-authority/dist/index.mjs
var nr = (e) => typeof e == "boolean" ? `${e}` : e === 0 ? "0" : e, rr = Re, ir = (e, t) => (n) => {
  if (t?.variants == null) return rr(e, n?.class, n?.className);
  let { variants: r, defaultVariants: i } = t, a = Object.keys(r).map((e) => {
    let t = n?.[e], a = i?.[e];
    if (t === null) return null;
    let o = nr(t) || nr(a);
    return r[e][o];
  }), o = n && Object.entries(n).reduce((e, t) => {
    let [n, r] = t;
    return r === void 0 || (e[n] = r), e;
  }, {});
  return rr(e, a, t?.compoundVariants?.reduce((e, t) => {
    let { class: n, className: r, ...a } = t;
    return Object.entries(a).every((e) => {
      let [t, n] = e;
      return Array.isArray(n) ? n.includes({
        ...i,
        ...o
      }[t]) : {
        ...i,
        ...o
      }[t] === n;
    }) ? [
      ...e,
      n,
      r
    ] : e;
  }, []), n?.class, n?.className);
}, ar = /* @__PURE__ */ o(((e) => {
  var t = Symbol.for("react.transitional.element"), n = Symbol.for("react.fragment");
  function r(e, n, r) {
    var i = null;
    if (r !== void 0 && (i = "" + r), n.key !== void 0 && (i = "" + n.key), "key" in n) for (var a in r = {}, n) a !== "key" && (r[a] = n[a]);
    else r = n;
    return n = r.ref, {
      $$typeof: t,
      type: e,
      key: i,
      ref: n === void 0 ? null : n,
      props: r
    };
  }
  e.Fragment = n, e.jsx = r, e.jsxs = r;
})), R = (/* @__PURE__ */ o(((e, t) => {
  t.exports = ar();
})))(), or = ir("badge", {
  variants: { tone: {
    default: "badge-default",
    success: "badge-success",
    warn: "badge-warn",
    danger: "badge-danger",
    info: "badge-info",
    muted: "badge-muted"
  } },
  defaultVariants: { tone: "default" }
});
function z({ className: e, tone: t, ...n }) {
  return /* @__PURE__ */ (0, R.jsx)("span", {
    className: fn(or({ tone: t }), e),
    ...n
  });
}
//#endregion
//#region apps/web/react/src/components/ui/button.tsx
var sr = ir("btn", {
  variants: {
    variant: {
      default: "btn-default",
      secondary: "btn-secondary",
      ghost: "btn-ghost",
      danger: "btn-danger"
    },
    size: {
      default: "btn-md",
      sm: "btn-sm",
      icon: "btn-icon"
    }
  },
  defaultVariants: {
    variant: "default",
    size: "default"
  }
}), B = C.forwardRef(({ className: e, variant: t, size: n, ...r }, i) => /* @__PURE__ */ (0, R.jsx)("button", {
  ref: i,
  className: fn(sr({
    variant: t,
    size: n
  }), e),
  ...r
}));
B.displayName = "Button";
function V({ className: e, variant: t, size: n, ...r }) {
  return /* @__PURE__ */ (0, R.jsx)("a", {
    className: fn(sr({
      variant: t,
      size: n
    }), e),
    ...r
  });
}
//#endregion
//#region apps/web/react/src/components/ui/select.tsx
function cr({ label: e, value: t, options: n, onChange: r, className: i }) {
  let [a, o] = (0, C.useState)(!1), s = (0, C.useRef)(null), c = (0, C.useRef)(null), l = (0, C.useId)(), u = n.find((e) => e.value === t) ?? n[0];
  (0, C.useEffect)(() => {
    function e(e) {
      s.current?.contains(e.target) || o(!1);
    }
    function t(e) {
      e.key === "Escape" && (o(!1), c.current?.focus());
    }
    return document.addEventListener("pointerdown", e), document.addEventListener("keydown", t), () => {
      document.removeEventListener("pointerdown", e), document.removeEventListener("keydown", t);
    };
  }, []);
  function d(e) {
    r(e), o(!1), c.current?.focus();
  }
  function f(e) {
    e.key === "ArrowDown" && (e.preventDefault(), o(!0), requestAnimationFrame(() => {
      s.current?.querySelector("[role=\"option\"]")?.focus();
    }));
  }
  return /* @__PURE__ */ (0, R.jsxs)("label", {
    className: fn("field", i),
    children: [/* @__PURE__ */ (0, R.jsx)("span", { children: e }), /* @__PURE__ */ (0, R.jsxs)("span", {
      className: fn("select-shell", a && "open"),
      ref: s,
      children: [
        /* @__PURE__ */ (0, R.jsx)("select", {
          className: "select-native",
          value: t,
          onChange: (e) => r(e.target.value),
          tabIndex: -1,
          "aria-hidden": "true",
          children: n.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
            value: e.value,
            children: e.label
          }, e.value))
        }),
        /* @__PURE__ */ (0, R.jsxs)("button", {
          ref: c,
          type: "button",
          className: "select-display",
          "aria-label": e,
          "aria-controls": l,
          "aria-expanded": a,
          "aria-haspopup": "listbox",
          onClick: () => o((e) => !e),
          onKeyDown: f,
          children: [/* @__PURE__ */ (0, R.jsxs)("span", {
            className: "select-copy",
            children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: u?.label }), u?.description ? /* @__PURE__ */ (0, R.jsx)("small", { children: u.description }) : null]
          }), /* @__PURE__ */ (0, R.jsx)(oe, { size: 16 })]
        }),
        /* @__PURE__ */ (0, R.jsx)("span", {
          id: l,
          className: "select-menu",
          role: "listbox",
          "aria-label": e,
          hidden: !a,
          children: n.map((e) => /* @__PURE__ */ (0, R.jsxs)("button", {
            type: "button",
            role: "option",
            "aria-selected": e.value === t,
            className: fn("select-option", e.value === t && "active"),
            onClick: () => d(e.value),
            onKeyDown: (e) => {
              e.key === "Escape" && (e.preventDefault(), o(!1), c.current?.focus());
            },
            children: [/* @__PURE__ */ (0, R.jsxs)("span", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.label }), e.description ? /* @__PURE__ */ (0, R.jsx)("small", { children: e.description }) : null] }), /* @__PURE__ */ (0, R.jsx)(ae, {
              size: 14,
              "aria-hidden": "true"
            })]
          }, e.value))
        })
      ]
    })]
  });
}
//#endregion
//#region apps/web/react/src/components/layout/brand.tsx
function lr() {
  return /* @__PURE__ */ (0, R.jsxs)("svg", {
    className: "brand-mark",
    viewBox: "0 0 32 32",
    fill: "none",
    "aria-hidden": "true",
    children: [
      /* @__PURE__ */ (0, R.jsx)("circle", {
        cx: "16",
        cy: "16",
        r: "14",
        stroke: "currentColor",
        strokeWidth: "2"
      }),
      /* @__PURE__ */ (0, R.jsx)("path", {
        d: "M16 4 L25 22 H7 Z",
        fill: "currentColor"
      }),
      /* @__PURE__ */ (0, R.jsx)("circle", {
        cx: "16",
        cy: "18",
        r: "3",
        fill: "var(--bg)"
      })
    ]
  });
}
function ur() {
  return /* @__PURE__ */ (0, R.jsxs)("a", {
    href: "/app",
    className: "brand",
    children: [/* @__PURE__ */ (0, R.jsx)(lr, {}), /* @__PURE__ */ (0, R.jsx)("span", { children: "AstraNull" })]
  });
}
//#endregion
//#region apps/web/react/src/components/layout/app-shell.tsx
var dr = [
  {
    value: "admin",
    label: "admin",
    description: "Full developer validation access"
  },
  {
    value: "engineer",
    label: "engineer",
    description: "Runs, agents, target groups"
  },
  {
    value: "soc",
    label: "soc",
    description: "SOC-gated workflow preview"
  },
  {
    value: "auditor",
    label: "auditor",
    description: "Evidence and audit visibility"
  },
  {
    value: "viewer",
    label: "viewer",
    description: "Read-only workspace"
  },
  {
    value: "owner",
    label: "owner",
    description: "Tenant owner access"
  }
];
function fr({ item: e, active: t, onClick: n }) {
  let r = e.icon;
  return /* @__PURE__ */ (0, R.jsxs)("button", {
    type: "button",
    className: fn("nav-item", t && "active"),
    onClick: n,
    title: e.label,
    children: [
      /* @__PURE__ */ (0, R.jsx)(r, { size: 16 }),
      /* @__PURE__ */ (0, R.jsx)("span", { children: e.label }),
      e.count ? /* @__PURE__ */ (0, R.jsx)("span", {
        className: "nav-count",
        children: e.count
      }) : null
    ]
  });
}
function pr({ route: e, session: t, data: n, onRouteChange: r, onRoleChange: i, onRefresh: a, children: o }) {
  let [s, c] = (0, C.useState)(!1), [l, u] = (0, C.useState)(() => {
    try {
      return window.localStorage.getItem("astranull.react.sidebar.collapsed") === "1";
    } catch {
      return !1;
    }
  }), d = Wn.get(e) ?? Un[0], f = t.principal === "staff" || e === "admin" || e === "internal-soc", p = e === "internal-soc" ? "Staff SOC execution surface" : f ? "Internal management console" : "Customer readiness console", m = (0, C.useMemo)(() => {
    let e = t.role ?? "admin";
    return Un.filter((n) => tr(e, n.id, {
      principal: t.principal,
      staffRole: t.staff_role
    }));
  }, [
    t.principal,
    t.role,
    t.staff_role
  ]), h = (0, C.useMemo)(() => m.reduce((e, t) => (e[t.group] = [...e[t.group] ?? [], t], e), {}), [m]);
  function g(e) {
    window.location.hash = e, r(e), c(!1);
  }
  function _() {
    Dn(), window.location.href = "/login";
  }
  function v() {
    u((e) => {
      let t = !e;
      try {
        window.localStorage.setItem("astranull.react.sidebar.collapsed", t ? "1" : "0");
      } catch {}
      return t;
    });
  }
  let y = l ? ve : _e;
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: fn("app-shell", l && "sidebar-collapsed"),
    children: [
      /* @__PURE__ */ (0, R.jsxs)("aside", {
        className: fn("sidebar", s && "open"),
        children: [
          /* @__PURE__ */ (0, R.jsx)(B, {
            variant: "secondary",
            size: "icon",
            className: "sidebar-collapse",
            onClick: v,
            "aria-label": l ? "Expand sidebar" : "Collapse sidebar",
            title: l ? "Expand sidebar" : "Collapse sidebar",
            children: /* @__PURE__ */ (0, R.jsx)(y, { size: 14 })
          }),
          /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "sidebar-head",
            children: [/* @__PURE__ */ (0, R.jsx)(ur, {}), /* @__PURE__ */ (0, R.jsx)(B, {
              variant: "ghost",
              size: "icon",
              className: "sidebar-close",
              onClick: () => c(!1),
              "aria-label": "Close navigation",
              children: /* @__PURE__ */ (0, R.jsx)(Fe, { size: 17 })
            })]
          }),
          /* @__PURE__ */ (0, R.jsx)("p", {
            className: "surface-label",
            children: p
          }),
          /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "tenant-card",
            children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", {
              className: "tenant-label",
              children: "Tenant"
            }), /* @__PURE__ */ (0, R.jsx)("strong", { children: t.tenant_id ?? n.state?.tenant_id ?? "ten_demo" })] }), /* @__PURE__ */ (0, R.jsx)(z, {
              tone: "success",
              children: "dev"
            })]
          }),
          /* @__PURE__ */ (0, R.jsx)(cr, {
            label: "Role",
            value: t.role ?? "admin",
            options: dr,
            onChange: i
          }),
          /* @__PURE__ */ (0, R.jsx)("nav", {
            className: "nav-scroll",
            "aria-label": "Portal",
            children: Object.keys(h).filter((e) => (h[e]?.length ?? 0) > 0).map((t) => /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "nav-group",
              children: [/* @__PURE__ */ (0, R.jsx)("p", { children: Hn[t] }), h[t]?.map((t) => /* @__PURE__ */ (0, R.jsx)(fr, {
                item: t,
                active: t.id === e,
                onClick: () => g(t.id)
              }, t.id))]
            }, t))
          }),
          /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "sidebar-foot",
            children: [/* @__PURE__ */ (0, R.jsx)("a", {
              href: "/",
              children: "Public site"
            }), /* @__PURE__ */ (0, R.jsx)("button", {
              type: "button",
              onClick: _,
              children: "Sign out"
            })]
          })
        ]
      }),
      /* @__PURE__ */ (0, R.jsx)("div", {
        className: fn("scrim", s && "open"),
        onClick: () => c(!1),
        "aria-hidden": "true"
      }),
      /* @__PURE__ */ (0, R.jsxs)("main", {
        className: "main",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("header", {
            className: "topbar",
            children: [
              /* @__PURE__ */ (0, R.jsx)(B, {
                variant: "ghost",
                size: "icon",
                className: "menu-btn",
                onClick: () => c(!0),
                "aria-label": "Open navigation",
                children: /* @__PURE__ */ (0, R.jsx)(he, { size: 18 })
              }),
              /* @__PURE__ */ (0, R.jsxs)("div", {
                className: "title-stack",
                children: [/* @__PURE__ */ (0, R.jsx)("div", {
                  className: "eyebrow",
                  children: "No-access-first · Evidence-backed · SOC-gated"
                }), /* @__PURE__ */ (0, R.jsx)("h1", { children: d.label })]
              }),
              /* @__PURE__ */ (0, R.jsxs)("div", {
                className: "topbar-actions",
                children: [/* @__PURE__ */ (0, R.jsxs)(z, {
                  tone: n.error ? "warn" : "success",
                  children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 12 }), n.error ? "Fallback data" : "Live workspace"]
                }), /* @__PURE__ */ (0, R.jsxs)(B, {
                  variant: "secondary",
                  size: "sm",
                  onClick: a,
                  children: [/* @__PURE__ */ (0, R.jsx)(Ce, { size: 14 }), "Refresh"]
                })]
              })
            ]
          }),
          /* @__PURE__ */ (0, R.jsx)("section", {
            className: "promise-strip",
            children: /* @__PURE__ */ (0, R.jsx)("p", { children: qn })
          }),
          o
        ]
      })
    ]
  });
}
//#endregion
//#region apps/web/react/src/components/ui/card.tsx
function H({ className: e, ...t }) {
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: fn("card", e),
    ...t
  });
}
function U({ className: e, ...t }) {
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: fn("card-header", e),
    ...t
  });
}
function W({ className: e, ...t }) {
  return /* @__PURE__ */ (0, R.jsx)("h3", {
    className: fn("card-title", e),
    ...t
  });
}
function G({ className: e, ...t }) {
  return /* @__PURE__ */ (0, R.jsx)("p", {
    className: fn("card-description", e),
    ...t
  });
}
function K({ className: e, ...t }) {
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: fn("card-content", e),
    ...t
  });
}
//#endregion
//#region apps/web/react/src/pages/public-pages.tsx
function mr({ title: e, robots: t }) {
  (0, C.useEffect)(() => {
    let n = document.title;
    document.title = e;
    let r = document.querySelector("meta[name=\"robots\"]"), i = r?.content, a = r;
    return t && (a || (a = document.createElement("meta"), a.name = "robots", document.head.appendChild(a)), a.content = t), () => {
      document.title = n, t && (i && a ? a.content = i : a && a.remove());
    };
  }, [e, t]);
}
function hr({ children: e, eyebrow: t = "No-access-first · Evidence-backed · SOC-gated", activeNav: n, loginHref: r = "/login", signupEnabled: i = !0 }) {
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "public-app",
    children: [/* @__PURE__ */ (0, R.jsx)("header", {
      className: "public-topnav",
      children: /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "public-topnav-inner",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("a", {
            href: "/",
            className: "brand",
            children: [/* @__PURE__ */ (0, R.jsx)(lr, {}), /* @__PURE__ */ (0, R.jsx)("span", { children: "AstraNull" })]
          }),
          /* @__PURE__ */ (0, R.jsx)("span", {
            className: "public-topnav-eyebrow eyebrow",
            children: t
          }),
          /* @__PURE__ */ (0, R.jsxs)("nav", {
            className: "public-topnav-actions",
            "aria-label": "Account access",
            children: [i ? /* @__PURE__ */ (0, R.jsx)(V, {
              href: "/signup",
              variant: n === "signup" ? "default" : "secondary",
              size: "sm",
              children: "Sign up"
            }) : null, /* @__PURE__ */ (0, R.jsx)(V, {
              href: r,
              variant: n === "login" ? "default" : "secondary",
              size: "sm",
              children: "Log in"
            })]
          })
        ]
      })
    }), e]
  });
}
function gr({ aside: e, children: t, footer: n, wide: r = !1 }) {
  return /* @__PURE__ */ (0, R.jsxs)("main", {
    className: `auth-page${r ? " auth-page--wide" : ""}`,
    children: [/* @__PURE__ */ (0, R.jsx)("aside", {
      className: "auth-aside",
      children: e
    }), /* @__PURE__ */ (0, R.jsxs)("section", {
      className: "auth-panel",
      children: [t, n ? /* @__PURE__ */ (0, R.jsx)("footer", {
        className: "auth-footer",
        children: n
      }) : null]
    })]
  });
}
function _r({ badge: e, title: t, description: n }) {
  return /* @__PURE__ */ (0, R.jsxs)(U, {
    className: "auth-card-header",
    children: [e, /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "auth-card-heading",
      children: [/* @__PURE__ */ (0, R.jsx)(W, { children: t }), /* @__PURE__ */ (0, R.jsx)(G, { children: n })]
    })]
  });
}
var vr = [
  {
    num: "01",
    title: "No-access-first",
    body: "You declare the target groups you want validated. AstraNull never defaults to cloud access and never auto-discovers your IP inventory. Validation uses outside probes and inside agents you place — nothing more."
  },
  {
    num: "02",
    title: "Evidence over assumptions",
    body: "Every verdict is backed by correlated probe results and agent observations, written to an evidence vault you control. Readiness is a number you can defend in an incident review — not a green checkmark."
  },
  {
    num: "03",
    title: "SOC-gated high-scale",
    body: "Default validation is low-volume, bounded, and non-disruptive. High-scale assessments are reviewed and executed by the AstraNull SOC after approval — customers submit requests, never run floods themselves."
  }
], yr = [
  {
    tag: "01 · Declare",
    title: "Scope your target groups",
    body: "Register environments and target groups — the FQDNs, DNS zones, and TCP surfaces you want validated. Declare expected behavior so verdicts map to your real edge topology."
  },
  {
    tag: "02 · Validate",
    title: "Place agents, run safe checks",
    body: "Install outbound-only agents and run the safe-by-default check catalog: origin-bypass, L3/L4, DNS, L7/API. Each check is bounded and metadata-only unless you escalate."
  },
  {
    tag: "03 · Evidence",
    title: "Correlate probe + agent",
    body: "Verdicts combine external probe reachability with internal agent path observation. Every result lands in the evidence vault, exportable for audits and incident reviews."
  },
  {
    tag: "04 · Govern",
    title: "Escalate through the SOC",
    body: "When you need high-scale validation, submit a request. The SOC reviews, schedules, and executes under a kill switch — with full custody and audit trail."
  }
], br = [
  [
    "Requires cloud credentials",
    "No — declared scope only",
    "Often",
    "Yes, read/write"
  ],
  [
    "Default probe posture",
    "Bounded & non-disruptive",
    "High-volume by default",
    "Passive metrics only"
  ],
  [
    "Inside + outside correlation",
    "Probes + placed agents",
    "Outside only",
    "Inside only"
  ],
  [
    "High-scale execution",
    "SOC-gated after approval",
    "Self-service",
    "Not available"
  ],
  [
    "Exportable evidence trail",
    "Evidence vault + custody",
    "Run logs",
    "Metric exports"
  ]
], xr = [{
  quote: "Regulated fintech that needs a defensible readiness number for audit — without granting a tool cloud credentials or letting it inventory production IPs.",
  attr: "Platform & security leads — declared-scope validation and evidence they can hand to an auditor."
}, {
  quote: "High-traffic media & CDN teams that want real high-scale assurance, but only under governance — no self-service floods pointed at production.",
  attr: "SRE & edge owners — SOC-governed high-scale, bounded probes the rest of the time."
}];
function Sr({ config: e }) {
  let t = String(e.siteConfig.product_name ?? "AstraNull"), n = String(e.siteConfig.promise ?? "AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery."), r = e.siteConfig.signup_enabled !== !1, i = e.loginUrl;
  return mr({ title: `${t} — Prove DDoS readiness without handing over your cloud keys` }), /* @__PURE__ */ (0, R.jsx)(hr, {
    eyebrow: "No-access-first · Evidence-backed · SOC-gated high-scale",
    loginHref: i,
    signupEnabled: r,
    children: /* @__PURE__ */ (0, R.jsxs)("main", {
      className: "public-wrap",
      children: [
        /* @__PURE__ */ (0, R.jsxs)("section", {
          className: "public-hero",
          children: [
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "eyebrow",
              children: "Defensive DDoS readiness validation"
            }),
            /* @__PURE__ */ (0, R.jsx)("h1", { children: "Prove DDoS readiness without handing over your cloud keys" }),
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "public-hero-lead",
              children: n
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "public-actions",
              children: [r ? /* @__PURE__ */ (0, R.jsxs)(V, {
                href: "/signup",
                children: ["Request access", /* @__PURE__ */ (0, R.jsx)(ee, { size: 15 })]
              }) : null, /* @__PURE__ */ (0, R.jsx)(V, {
                href: i,
                variant: "secondary",
                children: "Log in"
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "public-hero-meta",
              children: [
                /* @__PURE__ */ (0, R.jsxs)("span", { children: [/* @__PURE__ */ (0, R.jsx)(ae, { size: 16 }), "No cloud credentials required"] }),
                /* @__PURE__ */ (0, R.jsxs)("span", { children: [/* @__PURE__ */ (0, R.jsx)(ae, { size: 16 }), "Low-volume, bounded probes"] }),
                /* @__PURE__ */ (0, R.jsxs)("span", { children: [/* @__PURE__ */ (0, R.jsx)(ae, { size: 16 }), "SOC-governed high-scale"] })
              ]
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)("section", {
          className: "public-section",
          id: "principles",
          children: [
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "eyebrow",
              children: "Principles"
            }),
            /* @__PURE__ */ (0, R.jsx)("h2", { children: "A defensive readiness platform, not self-service attack tooling" }),
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "public-section-lead",
              children: "Three commitments shape every screen, every probe, every verdict in AstraNull."
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "public-pillars",
              children: vr.map((e) => /* @__PURE__ */ (0, R.jsxs)("article", {
                className: "public-pillar",
                children: [
                  /* @__PURE__ */ (0, R.jsx)("p", {
                    className: "public-pillar-num",
                    children: e.num
                  }),
                  /* @__PURE__ */ (0, R.jsx)("h3", { children: e.title }),
                  /* @__PURE__ */ (0, R.jsx)("p", { children: e.body })
                ]
              }, e.title))
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)("section", {
          className: "public-section",
          id: "how",
          children: [
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "eyebrow",
              children: "How it works"
            }),
            /* @__PURE__ */ (0, R.jsx)("h2", { children: "Declare · Validate · Evidence · Govern" }),
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "public-section-lead",
              children: "A four-stage loop that turns a declared scope into a defensible readiness posture."
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "public-flow",
              children: yr.map((e) => /* @__PURE__ */ (0, R.jsxs)("article", {
                className: "public-flow-step",
                children: [
                  /* @__PURE__ */ (0, R.jsx)("p", {
                    className: "public-flow-tag",
                    children: e.tag
                  }),
                  /* @__PURE__ */ (0, R.jsx)("h3", { children: e.title }),
                  /* @__PURE__ */ (0, R.jsx)("p", { children: e.body })
                ]
              }, e.tag))
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)("section", {
          className: "public-section public-section--narrow",
          id: "compare",
          children: [
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "eyebrow",
              children: "Why AstraNull"
            }),
            /* @__PURE__ */ (0, R.jsx)("h2", { children: "Built for teams that can't hand over the keys" }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "public-compare",
              children: /* @__PURE__ */ (0, R.jsxs)("table", { children: [/* @__PURE__ */ (0, R.jsx)("thead", { children: /* @__PURE__ */ (0, R.jsxs)("tr", { children: [
                /* @__PURE__ */ (0, R.jsx)("th", { scope: "col" }),
                /* @__PURE__ */ (0, R.jsx)("th", {
                  scope: "col",
                  children: "AstraNull"
                }),
                /* @__PURE__ */ (0, R.jsx)("th", {
                  scope: "col",
                  children: "Legacy load-testing"
                }),
                /* @__PURE__ */ (0, R.jsx)("th", {
                  scope: "col",
                  children: "Cloud DDoS dashboards"
                })
              ] }) }), /* @__PURE__ */ (0, R.jsx)("tbody", { children: br.map(([e, t, n, r]) => /* @__PURE__ */ (0, R.jsxs)("tr", { children: [
                /* @__PURE__ */ (0, R.jsx)("th", {
                  scope: "row",
                  children: e
                }),
                /* @__PURE__ */ (0, R.jsx)("td", {
                  className: "public-compare-yes",
                  children: t
                }),
                /* @__PURE__ */ (0, R.jsx)("td", { children: n }),
                /* @__PURE__ */ (0, R.jsx)("td", { children: r })
              ] }, e)) })] })
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)("section", {
          className: "public-section",
          children: [
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "eyebrow",
              children: "Who it's built for"
            }),
            /* @__PURE__ */ (0, R.jsx)("h2", { children: "Where the no-access model matters most" }),
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "public-section-lead",
              children: "Two profiles that keep hitting the wall between “prove the edge holds” and “don't hand a validation tool our cloud keys.”"
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "public-quotes",
              children: xr.map((e) => /* @__PURE__ */ (0, R.jsxs)("article", {
                className: "public-quote",
                children: [/* @__PURE__ */ (0, R.jsx)("blockquote", { children: e.quote }), /* @__PURE__ */ (0, R.jsx)("p", { children: e.attr })]
              }, e.attr))
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)("section", {
          className: "public-cta-final",
          children: [
            /* @__PURE__ */ (0, R.jsx)("h2", { children: "Prove your edge holds — before an attacker proves it doesn't." }),
            /* @__PURE__ */ (0, R.jsx)("p", { children: "Request access. We'll review your account and stand up a tenant with the full customer portal." }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "public-actions",
              children: [r ? /* @__PURE__ */ (0, R.jsx)(V, {
                href: "/signup",
                children: "Request access"
              }) : null, /* @__PURE__ */ (0, R.jsx)(V, {
                href: i,
                variant: "secondary",
                children: "Log in"
              })]
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)("footer", {
          className: "public-footer",
          children: [/* @__PURE__ */ (0, R.jsxs)("span", { children: [
            "© ",
            t,
            " — DDoS readiness validation. Defensive platform only."
          ] }), /* @__PURE__ */ (0, R.jsxs)("nav", {
            "aria-label": "Public footer",
            children: [/* @__PURE__ */ (0, R.jsx)("a", {
              href: i,
              children: "Log in"
            }), /* @__PURE__ */ (0, R.jsx)("a", {
              href: "#principles",
              children: "Principles"
            })]
          })]
        })
      ]
    })
  });
}
function Cr({ config: e }) {
  mr({ title: "Log in — AstraNull Customer Portal" });
  let [t, n] = (0, C.useState)("usr_admin"), [r, i] = (0, C.useState)("admin"), [a, o] = (0, C.useState)(""), [s, c] = (0, C.useState)(!1), l = e.authMode === "dev-headers", u = bn(e), d = (0, C.useMemo)(() => Cn(e, "customer"), [e]), f = u && !e.bundledLoginEnabled && !d;
  (0, C.useEffect)(() => {
    let t = Tn();
    t?.access_token && t.principal !== "staff" && window.location.replace(e.portalPath);
  }, [e.portalPath]), (0, C.useEffect)(() => {
    d && window.location.replace(d);
  }, [d]), (0, C.useEffect)(() => {
    f && o("Enterprise SSO is required for this deployment. Contact your administrator for a login link.");
  }, [f]);
  let p = l ? "Developer validation mode — continue with local tenant headers (no password required)." : e.bundledLoginEnabled ? "Bundled staging login mints a short-lived bearer session for this environment." : d ? "Redirecting to your organization sign-in provider." : "Sign-in is managed by your organization identity provider.";
  async function m(n) {
    if (n.preventDefault(), !f) {
      if (o(""), c(!0), l) {
        En({
          mode: "dev-headers",
          principal: "customer",
          tenant_id: "ten_demo",
          user_id: t.trim() || "usr_admin",
          role: r
        }), window.location.href = e.portalPath;
        return;
      }
      try {
        let n = await fetch("/v1/auth/bundled-staging-login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            accept: "application/json"
          },
          body: JSON.stringify({
            principal: "customer",
            tenant_id: "ten_demo",
            user_id: t.trim() || "usr_admin",
            role: r
          })
        }), i = await n.json().catch(() => ({}));
        if (!n.ok) throw Error(String(i.message ?? i.error ?? "Login failed."));
        En(wn(i)), window.location.href = e.portalPath;
      } catch (e) {
        o(e instanceof Error ? e.message : "Login failed."), c(!1);
      }
    }
  }
  return /* @__PURE__ */ (0, R.jsx)(hr, {
    eyebrow: "Customer portal",
    activeNav: "login",
    children: /* @__PURE__ */ (0, R.jsx)(gr, {
      aside: /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-kicker",
          children: "Customer workspace"
        }),
        /* @__PURE__ */ (0, R.jsx)("h1", {
          className: "auth-title",
          children: "Log in to your readiness console."
        }),
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-lead",
          children: l ? "Local developer validation uses tenant headers to preview RBAC without a password." : "Review declared targets, agent heartbeats, safe validation runs, and SOC-governed high-scale intake from one tenant-scoped surface."
        }),
        /* @__PURE__ */ (0, R.jsxs)("ul", {
          className: "auth-points",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 16 }), " Evidence-backed verdicts tied to observed probe data"] }),
            /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsx)(me, { size: 16 }), " No default cloud credentials required"] }),
            /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsx)(j, { size: 16 }), " Audit-ready exports and custody references"] })
          ]
        })
      ] }),
      footer: /* @__PURE__ */ (0, R.jsxs)("p", { children: [
        "Need an account? ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/signup",
          children: "Request access"
        }),
        " · ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/signup-status",
          children: "Check request status"
        })
      ] }),
      children: /* @__PURE__ */ (0, R.jsxs)(H, {
        className: "auth-card",
        children: [/* @__PURE__ */ (0, R.jsx)(_r, {
          badge: /* @__PURE__ */ (0, R.jsx)(z, {
            tone: "info",
            children: "Customer portal"
          }),
          title: "Log in to AstraNull",
          description: p
        }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "auth-form",
          onSubmit: m,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: l || e.bundledLoginEnabled ? "Work email / user ID" : "User ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
              value: t,
              onChange: (e) => n(e.target.value),
              autoComplete: "username",
              required: !f,
              disabled: f || !!d
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Tenant" }), /* @__PURE__ */ (0, R.jsx)("input", {
              value: "ten_demo",
              readOnly: !0,
              "aria-readonly": "true",
              disabled: f || !!d
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Role" }), /* @__PURE__ */ (0, R.jsx)("select", {
              value: r,
              onChange: (e) => i(e.target.value),
              disabled: f || !!d,
              children: [
                "admin",
                "engineer",
                "soc",
                "viewer",
                "auditor",
                "owner"
              ].map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: e,
                children: e
              }, e))
            })] }),
            a ? /* @__PURE__ */ (0, R.jsx)("p", {
              className: "form-error",
              role: "alert",
              children: a
            }) : null,
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "auth-form-actions",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: s || f || !!d,
                children: s ? "Signing in..." : "Continue to portal"
              })
            })
          ]
        }) })]
      })
    })
  });
}
function wr(e, t) {
  let n = String(t.error ?? "");
  return e === 429 || n === "rate_limited" ? "Too many sign-up attempts. Please try again later." : n === "duplicate_request" ? "A pending request already exists for this organization or email domain." : e === 403 || n === "signup_disabled" ? "Account requests are not being accepted right now. Contact your AstraNull representative." : n === "validation_failed" ? "Could not submit request. Check required fields and try again." : String(t.message ?? t.error ?? "Could not submit request.");
}
function Tr({ config: e }) {
  mr({ title: "Request access — AstraNull" });
  let t = e.siteConfig.signup_enabled !== !1, [n, r] = (0, C.useState)(null), [i, a] = (0, C.useState)("");
  async function o(e) {
    if (e.preventDefault(), !t) return;
    a("");
    let n = new FormData(e.currentTarget), i = {
      organization_name: n.get("organization_name"),
      contact_email: n.get("contact_email"),
      contact_name: n.get("contact_name"),
      requested_plan: n.get("requested_plan"),
      intended_use: n.get("intended_use"),
      region: n.get("region"),
      high_scale_interest: n.get("high_scale_interest") === "on"
    };
    try {
      let e = await fetch("/v1/signup-requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(i)
      }), t = await e.json().catch(() => ({}));
      if (!e.ok) throw Error(wr(e.status, t));
      r(t.request ?? t);
    } catch (e) {
      a(e instanceof Error ? e.message : "Could not submit request.");
    }
  }
  return /* @__PURE__ */ (0, R.jsx)(hr, {
    eyebrow: "Approval-gated account intake",
    activeNav: "signup",
    children: /* @__PURE__ */ (0, R.jsx)(gr, {
      wide: !0,
      aside: /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-kicker",
          children: "Account intake"
        }),
        /* @__PURE__ */ (0, R.jsx)("h1", {
          className: "auth-title",
          children: "Request governed validation access."
        }),
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-lead",
          children: "Provisioning is review-gated. Operations validates organization details, intended use, and plan fit before creating a tenant workspace."
        }),
        /* @__PURE__ */ (0, R.jsxs)("ul", {
          className: "auth-points",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 16 }), " Safe-by-default validation is available immediately after approval"] }),
            /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsx)(De, { size: 16 }), " High-scale programs stay SOC-scheduled and authorization-pack gated"] }),
            /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsx)(Me, { size: 16 }), " Track request status any time with your request ID"] })
          ]
        })
      ] }),
      footer: /* @__PURE__ */ (0, R.jsxs)("p", { children: [
        "Already have access? ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/login",
          children: "Log in"
        }),
        " · ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/signup-status",
          children: "Check request status"
        })
      ] }),
      children: /* @__PURE__ */ (0, R.jsxs)(H, {
        className: "auth-card auth-card--wide",
        children: [/* @__PURE__ */ (0, R.jsx)(_r, {
          badge: /* @__PURE__ */ (0, R.jsx)(z, {
            tone: "info",
            children: "Reviewed access"
          }),
          title: n ? "Request submitted" : "Request an AstraNull account",
          description: "Account creation is reviewed before provisioning a tenant."
        }), /* @__PURE__ */ (0, R.jsx)(K, { children: t ? n ? /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "success-panel",
          children: [
            /* @__PURE__ */ (0, R.jsx)(k, { size: 30 }),
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "success-panel-lead",
              children: "We provision reviewed accounts only. Save your request ID to check status any time."
            }),
            /* @__PURE__ */ (0, R.jsxs)("dl", { children: [
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Request ID" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.id ?? "submitted") })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.state ?? "submitted") })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Organization" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.organization_name ?? "Recorded") })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Requested plan" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.requested_plan ?? "professional") })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Region" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.region ?? "us") })] })
            ] }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "auth-form-actions row-actions",
              children: [/* @__PURE__ */ (0, R.jsx)(V, {
                href: "/signup-status",
                variant: "secondary",
                children: "Check status"
              }), /* @__PURE__ */ (0, R.jsx)(V, {
                href: "/",
                children: "Back to landing"
              })]
            })
          ]
        }) : /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "auth-form auth-form--grid",
          onSubmit: o,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Organization" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "organization_name",
              required: !0,
              placeholder: "Acme Corp",
              autoComplete: "organization"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Work email" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "contact_email",
              type: "email",
              required: !0,
              placeholder: "you@company.com",
              autoComplete: "email"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Primary contact" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "contact_name",
              required: !0,
              placeholder: "Jordan Lee",
              autoComplete: "name"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Requested plan" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "requested_plan",
              defaultValue: "professional",
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "starter",
                  children: "starter"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "professional",
                  children: "professional"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "enterprise",
                  children: "enterprise"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "auth-field-full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Intended use" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "intended_use",
                required: !0,
                rows: 4,
                placeholder: "Defensive DDoS readiness validation for declared production origins."
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Region" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "region",
              defaultValue: "us",
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "us",
                  children: "United States"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "eu",
                  children: "European Union"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "uk",
                  children: "United Kingdom"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "apac",
                  children: "Asia-Pacific"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "auth-field-full auth-check-row",
              children: [/* @__PURE__ */ (0, R.jsx)("input", {
                name: "high_scale_interest",
                type: "checkbox"
              }), /* @__PURE__ */ (0, R.jsx)("span", { children: "We may need SOC-governed high-scale validation." })]
            }),
            i ? /* @__PURE__ */ (0, R.jsx)("p", {
              className: "form-error auth-field-full",
              role: "alert",
              children: i
            }) : null,
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "auth-form-actions auth-field-full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                children: "Submit request"
              })
            })
          ]
        }) : /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "success-panel",
          children: [
            /* @__PURE__ */ (0, R.jsx)(Ae, { size: 30 }),
            /* @__PURE__ */ (0, R.jsx)("p", {
              className: "success-panel-lead",
              children: "Account intake is temporarily closed for this deployment. Existing customers can sign in; approved request IDs can still be checked on the status page."
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "auth-form-actions row-actions",
              children: [/* @__PURE__ */ (0, R.jsx)(V, {
                href: "/login",
                variant: "secondary",
                children: "Log in"
              }), /* @__PURE__ */ (0, R.jsx)(V, {
                href: "/signup-status",
                children: "Check request status"
              })]
            })
          ]
        }) })]
      })
    })
  });
}
function Er() {
  mr({ title: "Request status — AstraNull" });
  let [e, t] = (0, C.useState)(""), [n, r] = (0, C.useState)(null), [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(!1);
  async function c(t) {
    t.preventDefault(), a(""), r(null);
    let n = e.trim();
    if (!n) {
      a("Enter a request ID to check status.");
      return;
    }
    s(!0);
    try {
      let e = await fetch(`/v1/signup-requests/${encodeURIComponent(n)}`, { headers: { accept: "application/json" } }), t = await e.json().catch(() => ({}));
      if (!e.ok) throw Error(String(t.message ?? t.error ?? "Request status was not found."));
      r(t.request ?? t);
    } catch (e) {
      a(e instanceof Error ? e.message : "Request status was not found.");
    } finally {
      s(!1);
    }
  }
  return /* @__PURE__ */ (0, R.jsx)(hr, {
    eyebrow: "Self-service status lookup",
    children: /* @__PURE__ */ (0, R.jsx)(gr, {
      aside: /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-kicker",
          children: "Self-service"
        }),
        /* @__PURE__ */ (0, R.jsx)("h1", {
          className: "auth-title",
          children: "Sign-up status"
        }),
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-lead",
          children: "Track your account request. You'll find the request ID in the confirmation panel shown after you submit the intake form, or in the email we sent to the work address you registered."
        })
      ] }),
      footer: /* @__PURE__ */ (0, R.jsxs)("p", { children: [
        "Lost your request ID? ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/signup",
          children: "Re-submit the intake"
        }),
        " · ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/login",
          children: "Log in"
        })
      ] }),
      children: /* @__PURE__ */ (0, R.jsxs)(H, {
        className: "auth-card",
        children: [/* @__PURE__ */ (0, R.jsx)(_r, {
          badge: /* @__PURE__ */ (0, R.jsx)(z, {
            tone: "info",
            children: "Status lookup"
          }),
          title: "Check request status",
          description: "Account provisioning remains review-gated and every status change is reviewed by operations."
        }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "auth-form",
          onSubmit: c,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [
              /* @__PURE__ */ (0, R.jsx)("span", { children: "Request ID" }),
              /* @__PURE__ */ (0, R.jsx)("input", {
                value: e,
                onChange: (e) => t(e.target.value),
                placeholder: "sgn_… (from your confirmation)",
                className: "mono",
                autoComplete: "off",
                required: !0
              }),
              /* @__PURE__ */ (0, R.jsx)("span", {
                className: "auth-field-help",
                children: "Use the ID returned after intake submission. Case-sensitive."
              })
            ] }),
            i ? /* @__PURE__ */ (0, R.jsx)("p", {
              className: "form-error",
              role: "alert",
              children: i
            }) : null,
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "auth-form-actions",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: o,
                children: o ? "Checking..." : "Look up status"
              })
            }),
            n ? /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "success-panel",
              children: [/* @__PURE__ */ (0, R.jsxs)("dl", { children: [
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Request ID" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.id ?? e) })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.state ?? n.status ?? "recorded") })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Organization" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.organization_name ?? n.organization ?? "Not recorded") })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Requested plan" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.requested_plan ?? "Not recorded") })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("dt", { children: "Region" }), /* @__PURE__ */ (0, R.jsx)("dd", { children: String(n.region ?? "Not recorded") })] })
              ] }), n.customer_notice ? /* @__PURE__ */ (0, R.jsx)("p", {
                className: "auth-field-help",
                children: String(n.customer_notice)
              }) : null]
            }) : null
          ]
        }) })]
      })
    })
  });
}
function Dr({ config: e }) {
  mr({
    title: "Staff sign-in — AstraNull Internal",
    robots: "noindex, nofollow"
  });
  let [t, n] = (0, C.useState)("staff_admin"), [r, i] = (0, C.useState)("internal_admin"), [a, o] = (0, C.useState)(""), [s, c] = (0, C.useState)(!1), l = e.authMode === "dev-headers", u = bn(e), d = (0, C.useMemo)(() => Cn(e, "staff"), [e]), f = u && !e.bundledLoginEnabled && !d, p = typeof window < "u" ? window.location.pathname : e.staffLoginPath;
  (0, C.useEffect)(() => {
    let e = Tn();
    e?.access_token && e.principal === "staff" && window.location.replace("/internal/admin");
  }, []), (0, C.useEffect)(() => {
    d && window.location.replace(d);
  }, [d]), (0, C.useEffect)(() => {
    f && o("Staff SSO is required for this deployment.");
  }, [f]);
  let m = l ? "Developer validation mode — continue with staff dev headers (no password required)." : e.bundledLoginEnabled ? "Bundled staging login mints a short-lived staff bearer session for this environment." : d ? "Redirecting to your organization staff sign-in provider." : "Staff sign-in is managed by your organization identity provider.";
  async function h(e) {
    if (e.preventDefault(), !f) {
      if (o(""), c(!0), l) {
        En({
          mode: "dev-headers",
          principal: "staff",
          staff_id: t.trim() || "staff_admin",
          staff_role: r,
          staff_login_path: p
        }), window.location.href = "/internal/admin";
        return;
      }
      try {
        let e = await fetch("/v1/auth/bundled-staging-login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            accept: "application/json"
          },
          body: JSON.stringify({
            principal: "staff",
            staff_id: t.trim() || "staff_admin",
            staff_role: r
          })
        }), n = await e.json().catch(() => ({}));
        if (!e.ok) throw Error(String(n.message ?? n.error ?? "Staff login failed."));
        En({
          ...wn(n),
          staff_login_path: p
        }), window.location.href = "/internal/admin";
      } catch (e) {
        o(e instanceof Error ? e.message : "Staff login failed."), c(!1);
      }
    }
  }
  return /* @__PURE__ */ (0, R.jsx)(hr, {
    eyebrow: "Internal staff access",
    children: /* @__PURE__ */ (0, R.jsx)(gr, {
      aside: /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-kicker",
          children: "Staff plane"
        }),
        /* @__PURE__ */ (0, R.jsx)("h1", {
          className: "auth-title",
          children: "Sign in to internal management."
        }),
        /* @__PURE__ */ (0, R.jsx)("p", {
          className: "auth-lead",
          children: l ? "Local developer validation uses staff headers to preview internal RBAC without a password." : "Review signup intake, tenant lifecycle, entitlement grants, approval queues, and internal audit from a separate staff surface."
        }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "staff-callout",
          role: "note",
          children: [/* @__PURE__ */ (0, R.jsx)(Ae, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "This surface performs provisioning and approval decisions. All actions are written to the internal audit log." })]
        })
      ] }),
      footer: /* @__PURE__ */ (0, R.jsxs)("p", { children: [
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/",
          children: "Back to site"
        }),
        " · ",
        /* @__PURE__ */ (0, R.jsx)("a", {
          href: "/login",
          children: "Customer login"
        })
      ] }),
      children: /* @__PURE__ */ (0, R.jsxs)(H, {
        className: "auth-card",
        children: [/* @__PURE__ */ (0, R.jsx)(_r, {
          badge: /* @__PURE__ */ (0, R.jsx)(z, {
            tone: "warn",
            children: "Staff only"
          }),
          title: "Staff sign-in",
          description: m
        }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "auth-form",
          onSubmit: h,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Staff ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
              value: t,
              onChange: (e) => n(e.target.value),
              autoComplete: "username",
              required: !f,
              disabled: f || !!d
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Staff role" }), /* @__PURE__ */ (0, R.jsx)("select", {
              value: r,
              onChange: (e) => i(e.target.value),
              disabled: f || !!d,
              children: [
                "internal_admin",
                "billing_ops",
                "support_engineer",
                "security_admin",
                "soc_analyst",
                "soc_lead"
              ].map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: e,
                children: e
              }, e))
            })] }),
            a ? /* @__PURE__ */ (0, R.jsx)("p", {
              className: "form-error",
              role: "alert",
              children: a
            }) : null,
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "auth-form-actions",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: s || f || !!d,
                children: s ? "Signing in..." : "Continue to internal admin"
              })
            })
          ]
        }) })]
      })
    })
  });
}
//#endregion
//#region apps/web/react/src/components/ui/empty-state.tsx
function q({ icon: e, title: t, body: n, actionLabel: r, actionHref: i }) {
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "empty-state",
    children: [
      /* @__PURE__ */ (0, R.jsx)(e, {
        className: "empty-icon",
        size: 36
      }),
      /* @__PURE__ */ (0, R.jsx)("h3", { children: t }),
      /* @__PURE__ */ (0, R.jsx)("p", { children: n }),
      r && i ? /* @__PURE__ */ (0, R.jsx)(V, {
        href: i,
        variant: "secondary",
        size: "sm",
        children: r
      }) : null
    ]
  });
}
//#endregion
//#region apps/web/react/src/components/ui/progress.tsx
function Or({ value: e, className: t }) {
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: fn("progress", t),
    "aria-valuenow": gn(e),
    "aria-valuemin": 0,
    "aria-valuemax": 100,
    children: /* @__PURE__ */ (0, R.jsx)("span", { style: { width: `${gn(e)}%` } })
  });
}
//#endregion
//#region apps/web/react/src/components/ui/table.tsx
function kr({ columns: e }) {
  return /* @__PURE__ */ (0, R.jsx)("thead", { children: /* @__PURE__ */ (0, R.jsx)("tr", { children: e.map((e) => /* @__PURE__ */ (0, R.jsx)("th", { children: e.label }, e.key)) }) });
}
function J({ columns: e, items: t, empty: n, className: r }) {
  return t.length === 0 ? /* @__PURE__ */ (0, R.jsxs)("div", {
    className: fn("table-wrap", r),
    children: [/* @__PURE__ */ (0, R.jsx)("table", { children: /* @__PURE__ */ (0, R.jsx)(kr, { columns: e }) }), n]
  }) : /* @__PURE__ */ (0, R.jsx)("div", {
    className: fn("table-wrap", r),
    children: /* @__PURE__ */ (0, R.jsxs)("table", { children: [/* @__PURE__ */ (0, R.jsx)(kr, { columns: e }), /* @__PURE__ */ (0, R.jsx)("tbody", { children: t.map((t, n) => /* @__PURE__ */ (0, R.jsx)("tr", { children: e.map((e) => /* @__PURE__ */ (0, R.jsx)("td", { children: e.render(t) }, e.key)) }, n)) })] })
  });
}
//#endregion
//#region apps/web/react/src/components/ui/tabs.tsx
function Ar({ value: e, options: t, onChange: n, className: r }) {
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: fn("tabs", r),
    role: "tablist",
    children: t.map((t) => /* @__PURE__ */ (0, R.jsx)("button", {
      type: "button",
      role: "tab",
      "aria-selected": t.id === e,
      className: fn("tab", t.id === e && "active"),
      onClick: () => n(t.id),
      children: t.label
    }, t.id))
  });
}
//#endregion
//#region apps/web/react/src/lib/route-params.ts
function jr(e = "") {
  let t = window.location.hash.replace(/^#/, ""), n = t.includes("?") ? t.slice(t.indexOf("?") + 1) : "", r = new URLSearchParams(n || window.location.search);
  return r.get("id") ?? r.get("entity_id") ?? e;
}
function Mr(e, t) {
  let n = encodeURIComponent(t);
  return `${window.location.pathname}${window.location.search}#${e}?id=${n}`;
}
//#endregion
//#region apps/web/react/src/lib/verdict-explanation.ts
function Nr(e, t, n = "") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Pr(e, t, n = "") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
function Fr(e) {
  let t = e.metadata ?? {};
  for (let e of [
    "observation_mode",
    "mode",
    "source",
    "interface",
    "log_source"
  ]) {
    let n = t[e];
    if (n != null && n !== "") return String(n);
  }
  return Nr(e, ["signal_type"], "event");
}
function Ir(e) {
  return e.length ? e.map((e) => {
    let t = [];
    e.timestamp && t.push(String(e.timestamp)), e.source && t.push(`source ${String(e.source)}`);
    let n = e.metadata ?? {}, r = e.external_result ?? n.external_result;
    return r && t.push(`external_result ${String(r)}`), n.probe_profile_kind && t.push(`profile ${String(n.probe_profile_kind)}`), n.simulation && t.push(String(n.simulation)), n.note && t.push(String(n.note)), t.length ? t.join(" · ") : Nr(e, ["signal_type"], "probe_result");
  }).join("; ") : "No probe_result events recorded for this run yet; external probe evidence is missing or limited.";
}
function Lr(e, t) {
  let n = [];
  return e.length ? e.forEach((e) => {
    let t = [];
    e.timestamp && t.push(String(e.timestamp)), e.agent_id && t.push(`agent ${String(e.agent_id)}`), e.source && t.push(`source ${String(e.source)}`), e.nonce_hash && t.push("nonce correlated");
    let r = e.metadata ?? {};
    r.reason && t.push(String(r.reason)), n.push(t.length ? t.join(" · ") : "agent_observation recorded");
  }) : n.push("No agent_observation events in this run timeline."), t.forEach((e) => {
    let t = e.metadata ?? {}, r = t.reason ? String(t.reason) : "no observation within bounded window";
    n.push(`agent_no_observation · ${r}`);
  }), n.join("; ");
}
function Rr(e) {
  let t = e.filter((e) => ["agent_observation", "agent_no_observation"].includes(Nr(e, ["signal_type"]))), n = t.length ? t : e;
  return n.length ? [...new Set(n.map((e) => Fr(e)))].join(", ") : "Observation mode cannot be determined — no agent or probe events yet.";
}
function zr(e, t, n) {
  if (n && typeof n == "object") {
    let e = [];
    if (n.level && e.push(String(n.level)), n.observation_mode && e.push(`mode ${String(n.observation_mode)}`), n.reason && e.push(String(n.reason)), n.agent_id && e.push(`agent ${String(n.agent_id)}`), e.length) return e.join(" · ");
  }
  return e.length ? "Placement confidence is supported by job-bound agent observation correlated to this run." : t.length ? "Placement confidence is limited: bounded window ended with agent_no_observation and no matching observation." : "Placement confidence cannot be proven from run events yet.";
}
function Br(e, t, n = {}) {
  if (!e?.verdict || typeof e.verdict != "object") return [];
  let r = t.filter((e) => Nr(e, ["signal_type"]) === "probe_result"), i = t.filter((e) => Nr(e, ["signal_type"]) === "agent_observation"), a = t.filter((e) => Nr(e, ["signal_type"]) === "agent_no_observation"), o = Pr(e, ["correlation", "nonce_hash"], ""), s = o ? i.filter((e) => Nr(e, ["nonce_hash"], "") === o) : i, c = e.verdict, l = n.remediationTemplate ?? Nr(e, ["remediation_template"], ""), u = `${Nr(c, ["verdict"], "—")} · confidence ${Nr(c, ["confidence"], "—")}. ${Nr(c, ["explanation"], "")}`.trim();
  return [
    {
      label: "External probe evidence",
      value: Ir(r)
    },
    {
      label: "Internal agent evidence",
      value: Lr(i, a)
    },
    {
      label: "Observation mode",
      value: Rr(t)
    },
    {
      label: "Placement confidence",
      value: zr(s, a, c.placement_confidence)
    },
    {
      label: "Conclusion",
      value: u
    },
    {
      label: "Remediation",
      value: l || "No remediation template recorded for this run."
    }
  ];
}
function Vr(e) {
  return e === "misplaced_agent" ? "misplaced" : e;
}
function Hr(e, t) {
  return t ? t === "protected" ? e === "probe" || e === "edge" ? "ok" : "muted" : t === "bypassable" || t === "penetrated" ? e === "probe" ? "ok" : e === "origin" ? "danger" : "warn" : "warn" : e === "probe" ? "ok" : "muted";
}
var Ur = [
  {
    key: "protected",
    description: "Blocked before origin; observation absent or consistent with policy."
  },
  {
    key: "bypassable",
    description: "Edge did not stop traffic; origin/agent observed the marker."
  },
  {
    key: "penetrated",
    description: "Protection failed; unwanted reach confirmed by evidence."
  },
  {
    key: "misplaced",
    description: "Agent or canary placement does not match the declared protected path."
  }
], Wr = [
  {
    key: "probe",
    label: "External probe",
    sub: "sent"
  },
  {
    key: "edge",
    label: "CDN / WAF",
    sub: "blocked?"
  },
  {
    key: "lb",
    label: "Load balancer",
    sub: "forwarded?"
  },
  {
    key: "origin",
    label: "Origin / agent",
    sub: "observed?"
  }
];
function Gr(e, t, n = "") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Kr(e, t, n = "") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
function qr({ detail: e }) {
  let t = Kr(e, ["verdict", "verdict"], ""), n = Kr(e, ["verdict", "confidence"], ""), r = t ? `Verdict evidence: ${t}${n ? ` (${n})` : ""}` : "Awaiting correlated probe and agent evidence.";
  return /* @__PURE__ */ (0, R.jsxs)("section", {
    className: "traffic-path",
    "aria-label": "Traffic path diagram",
    children: [
      /* @__PURE__ */ (0, R.jsx)("h4", { children: "Traffic path" }),
      /* @__PURE__ */ (0, R.jsx)("div", {
        className: "traffic-path-track",
        children: Wr.map((e, n) => /* @__PURE__ */ (0, R.jsxs)("span", {
          className: "traffic-path-hop",
          children: [n > 0 ? /* @__PURE__ */ (0, R.jsx)("span", {
            className: "traffic-path-arrow",
            "aria-hidden": "true",
            children: "→"
          }) : null, /* @__PURE__ */ (0, R.jsxs)("div", {
            className: `traffic-path-node traffic-path-node--${Hr(e.key, t)}`,
            children: [/* @__PURE__ */ (0, R.jsx)("span", {
              className: "traffic-path-label",
              children: e.label
            }), /* @__PURE__ */ (0, R.jsx)("span", {
              className: "traffic-path-sub muted",
              children: e.sub
            })]
          })]
        }, e.key))
      }),
      /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted traffic-path-caption",
        children: r
      })
    ]
  });
}
function Jr({ detail: e, events: t, heading: n = "Why this verdict?" }) {
  if (!e?.verdict) return /* @__PURE__ */ (0, R.jsxs)("section", {
    className: "verdict-explanation verdict-explanation--pending",
    children: [/* @__PURE__ */ (0, R.jsx)("h4", { children: n }), /* @__PURE__ */ (0, R.jsx)("p", {
      className: "muted",
      children: "Verdict evidence is still pending for this run."
    })]
  });
  let r = Br(e, t);
  return /* @__PURE__ */ (0, R.jsxs)("section", {
    className: "verdict-explanation",
    children: [/* @__PURE__ */ (0, R.jsx)("h4", { children: n }), /* @__PURE__ */ (0, R.jsx)("div", {
      className: "verdict-explanation-grid",
      children: r.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "verdict-explanation-item",
        children: [/* @__PURE__ */ (0, R.jsx)("span", {
          className: "verdict-explanation-label",
          children: e.label
        }), /* @__PURE__ */ (0, R.jsx)("span", {
          className: "verdict-explanation-value",
          children: e.value
        })]
      }, e.label))
    })]
  });
}
function Yr({ detail: e }) {
  let t = Vr(Kr(e, ["verdict", "verdict"], ""));
  return /* @__PURE__ */ (0, R.jsxs)("section", {
    className: "truth-table-viz",
    children: [/* @__PURE__ */ (0, R.jsx)("h4", { children: "Verdict truth table" }), /* @__PURE__ */ (0, R.jsxs)("table", {
      className: "truth-table data-table",
      children: [/* @__PURE__ */ (0, R.jsx)("thead", { children: /* @__PURE__ */ (0, R.jsxs)("tr", { children: [/* @__PURE__ */ (0, R.jsx)("th", { children: "Outcome" }), /* @__PURE__ */ (0, R.jsx)("th", { children: "Meaning (evidence-oriented)" })] }) }), /* @__PURE__ */ (0, R.jsx)("tbody", { children: Ur.map((e) => /* @__PURE__ */ (0, R.jsxs)("tr", {
        className: t === e.key ? "truth-row truth-row--active" : "truth-row",
        children: [/* @__PURE__ */ (0, R.jsx)("td", { children: /* @__PURE__ */ (0, R.jsx)("span", {
          className: `truth-outcome truth-outcome--${e.key}`,
          children: e.key
        }) }), /* @__PURE__ */ (0, R.jsx)("td", { children: e.description })]
      }, e.key)) })]
    })]
  });
}
function Xr({ events: e }) {
  if (!e.length) return /* @__PURE__ */ (0, R.jsx)("div", {
    className: "run-timeline-viz empty muted",
    children: "No timeline events yet."
  });
  let t = e.length - 1;
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "run-timeline-viz",
    "aria-label": "Run event timeline",
    children: [/* @__PURE__ */ (0, R.jsx)("div", {
      className: "run-timeline-rail",
      children: e.map((e, n) => {
        let r = t ? n / t * 100 : 50, i = `${Gr(e, ["signal_type", "type"], "event")} · ${I(e.timestamp ?? e.created_at).slice(11, 19) || "—"}`;
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "run-timeline-marker",
          style: { left: `${r}%` },
          children: [/* @__PURE__ */ (0, R.jsx)("span", { className: "run-timeline-dot" }), /* @__PURE__ */ (0, R.jsx)("span", {
            className: "run-timeline-tip",
            children: i
          })]
        }, Gr(e, ["id"], String(n)));
      })
    }), /* @__PURE__ */ (0, R.jsx)("ol", {
      className: "run-timeline-list",
      children: e.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("li", { children: [
        I(e.timestamp ?? e.created_at),
        " · ",
        Gr(e, ["signal_type", "type"], "event"),
        " · ",
        Gr(e, ["source"], "")
      ] }, Gr(e, ["id"], String(t))))
    })]
  });
}
function Zr({ detail: e, events: t }) {
  return e ? /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "run-proof-panels",
    children: [
      /* @__PURE__ */ (0, R.jsx)(qr, { detail: e }),
      /* @__PURE__ */ (0, R.jsx)(Jr, {
        detail: e,
        events: t
      }),
      /* @__PURE__ */ (0, R.jsx)(Yr, { detail: e })
    ]
  }) : null;
}
//#endregion
//#region apps/web/react/src/lib/onboarding.ts
var Qr = 3e3, $r = "path.protected_canary.safe";
function ei(e, t = Date.now()) {
  if (!e || ai(e, ["status"]) !== "online") return !1;
  let n = e.last_heartbeat_at;
  if (!n) return !1;
  let r = t - Date.parse(String(n));
  return Number.isFinite(r) && r >= 0 && r < 12e4;
}
function ti(e, t = {}) {
  let n = t.nowMs ?? Date.now(), r = t.pollStartedAt ?? n, i = e ?? [], a = i.filter((e) => ei(e, n)), o = Math.max(0, n - r);
  return a.length ? {
    status: "online",
    agents: a,
    elapsedMs: o
  } : o >= 12e4 ? {
    status: "timeout",
    agents: i,
    elapsedMs: o
  } : {
    status: i.some((e) => e.last_heartbeat_at && !ei(e, n)) ? "stale" : "waiting",
    agents: i,
    elapsedMs: o
  };
}
function ni(e) {
  let t = (Array.isArray(e?.factors) ? e.factors : []).find((e) => ai(e, ["key"]) === "agent_placement")?.placement_diagnostics;
  return t && typeof t == "object" && !Array.isArray(t) ? t : null;
}
function ri(e, t) {
  let n = Array.isArray(t?.groups) ? t.groups : [];
  return n.some((e) => ai(e, ["status"]) === "proven") ? "Placement confidence is supported: baseline traffic was observed for a declared target group." : (Array.isArray(e?.capabilities) ? e.capabilities : []).includes("canary") ? "Canary-capable agent detected — placement confidence improves when protected-path canary traffic is observed." : n.some((e) => ai(e, ["status"]) === "needs_baseline") ? "Placement confidence is limited until baseline or canary traffic is seen — run the optional placement test." : e ? "Heartbeat received. Run the optional placement test to strengthen placement confidence before the first validation." : "Placement confidence cannot be proven yet — verify agent bind, observation mode, and protected-path visibility.";
}
function ii(e) {
  return e.some((e) => ai(e, ["check_id"]) === "path.protected_canary.safe" && [
    "completed",
    "verdicted",
    "running"
  ].includes(ai(e, ["status"])));
}
function ai(e, t) {
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return "";
}
//#endregion
//#region apps/web/react/src/lib/agent-helpers.ts
function oi(e, t, n = "—") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function si(e, t, n = "") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
function ci(e) {
  let t = Array.isArray(e?.capabilities) ? e.capabilities : [];
  return t.length ? t.join(", ") : "—";
}
function li(e) {
  return oi(e, ["placement_type", "placement"], "") || "undeclared";
}
function ui(e) {
  return oi(e, ["status", "state"], "unknown");
}
function di(e, t = Date.now()) {
  return e ? oi(e, ["status"]) === "revoked" ? "revoked" : ei(e, t) ? "fresh" : e.last_heartbeat_at ? "stale" : "never" : "unknown";
}
function fi(e) {
  let t = e?.readiness, n = (Array.isArray(t?.factors) ? t.factors : []).find((e) => oi(e, ["key"]) === "agent_placement");
  if (!n) return null;
  let r = n.score;
  return typeof r == "number" && Number.isFinite(r) ? Math.round(r) : null;
}
function pi(e, t) {
  return e.filter((e) => {
    let n = oi(e, ["resource_type"], ""), r = oi(e, ["action"], ""), i = oi(e, ["resource_id"], "");
    return n === "agent" || r.startsWith("agent.") || r.startsWith("agent_update.") ? t ? i === t || si(e, ["metadata", "agent_id"]) === t : !0 : !1;
  });
}
function mi() {
  return typeof window < "u" ? window.location.origin : "";
}
//#endregion
//#region apps/web/react/src/lib/prototype-manifest.ts
var hi = {
  dashboard: [
    {
      id: "overview",
      label: "Overview",
      summary: "Readiness score, open gaps, and current operating state.",
      evidence: "Readiness factors, findings, runs, and evidence counts."
    },
    {
      id: "business-services",
      label: "Business Services",
      summary: "Declared groups mapped to owner, environment, and readiness.",
      evidence: "Customer declarations plus target-group records."
    },
    {
      id: "risk-trends",
      label: "Risk Trends",
      summary: "Score trend, vector coverage, and aging finding pressure.",
      evidence: "Run and finding history."
    },
    {
      id: "evidence-feed",
      label: "Evidence Feed",
      summary: "Newest evidence, custody events, and report-ready artifacts.",
      evidence: "Evidence ledger and audit activity."
    }
  ],
  "target-groups": [
    {
      id: "overview",
      label: "Overview",
      summary: "Declared target groups with readiness and owner context.",
      evidence: "Customer-provided scope declaration."
    },
    {
      id: "targets",
      label: "Targets",
      summary: "Manual or CSV/API-imported targets only.",
      evidence: "Declared targets and explicit expected behavior."
    },
    {
      id: "expected-behavior",
      label: "Expected Behavior",
      summary: "Expected paths, health signals, and protective baseline.",
      evidence: "Customer declaration and observed safe checks."
    },
    {
      id: "agents",
      label: "Agents",
      summary: "Outbound observers bound to declared scope.",
      evidence: "Agent heartbeat and placement confidence."
    },
    {
      id: "checks",
      label: "Checks",
      summary: "Safe check bindings and coverage.",
      evidence: "Check catalog and policy bindings."
    },
    {
      id: "runs",
      label: "Runs",
      summary: "Recent safe validation activity.",
      evidence: "Run timeline and verdicts."
    },
    {
      id: "findings",
      label: "Findings",
      summary: "Open and closed gaps for this group.",
      evidence: "Finding custody references."
    },
    {
      id: "settings",
      label: "Settings",
      summary: "Archive, owners, windows, and safety policy.",
      evidence: "Audited tenant action."
    }
  ],
  agents: [
    {
      id: "install",
      label: "Install",
      summary: "Bootstrap-token install commands for Linux, Docker, and Kubernetes.",
      evidence: "One-time token issuance and install proof."
    },
    {
      id: "fleet",
      label: "Fleet",
      summary: "Online, stale, and versioned agent inventory.",
      evidence: "Outbound heartbeat and agent records."
    },
    {
      id: "health",
      label: "Health",
      summary: "Heartbeat freshness, gateway trust, and diagnostic state.",
      evidence: "Agent health and mTLS gateway evidence."
    },
    {
      id: "placement",
      label: "Placement",
      summary: "Confidence that the agent observes the right traffic path.",
      evidence: "Canary and placement diagnostics."
    },
    {
      id: "capabilities",
      label: "Capabilities",
      summary: "Supported observation and metadata signals.",
      evidence: "Agent capability report."
    },
    {
      id: "logs",
      label: "Logs",
      summary: "Audit-safe operational log summaries.",
      evidence: "Metadata-only event references."
    },
    {
      id: "upgrades",
      label: "Upgrades",
      summary: "Version rollout, rollback, and package provenance.",
      evidence: "SBOM and release evidence."
    }
  ],
  checks: [
    {
      id: "recommended",
      label: "Recommended",
      summary: "Starter checks based on declared service context.",
      evidence: "Check catalog safety class and target bindings."
    },
    {
      id: "origin-bypass",
      label: "Origin Bypass",
      summary: "Bounded origin protection checks.",
      evidence: "Probe metadata and agent observation."
    },
    {
      id: "l3l4",
      label: "L3/L4",
      summary: "Low-volume TCP and reachability validation families.",
      evidence: "Bounded probe results."
    },
    {
      id: "dns",
      label: "DNS",
      summary: "Resolver and delegation readiness checks.",
      evidence: "DNS lookup metadata."
    },
    {
      id: "l7api",
      label: "L7/API",
      summary: "Safe application path and API posture checks.",
      evidence: "HEAD/marker observations without sensitive content."
    },
    {
      id: "protocols",
      label: "Protocols",
      summary: "TLS and protocol hygiene checks.",
      evidence: "Handshake and metadata observations."
    },
    {
      id: "high-scale",
      label: "High-Scale",
      summary: "Request-only scenarios that require SOC governance.",
      evidence: "Authorization pack and SOC decision artifacts."
    },
    {
      id: "custom",
      label: "Custom",
      summary: "Customer-defined safe checks bound to declarations.",
      evidence: "Policy record and reviewed scope."
    }
  ],
  "test-policies": [
    {
      id: "cadence",
      label: "Cadence",
      summary: "Daily, weekly, monthly, and event-driven safe validation windows.",
      evidence: "Policy schedule and target binding."
    },
    {
      id: "bindings",
      label: "Target Bindings",
      summary: "Policies bind only to declared target groups.",
      evidence: "Declared target-group reference."
    },
    {
      id: "expected-verdicts",
      label: "Expected Verdicts",
      summary: "Expected pass, warn, or fail behavior for each safe check.",
      evidence: "Customer declaration and check contract."
    },
    {
      id: "windows",
      label: "Safe Windows",
      summary: "Local maintenance and observation windows.",
      evidence: "Policy record and audit."
    },
    {
      id: "guardrails",
      label: "Guardrails",
      summary: "Low-volume and bounded validation settings.",
      evidence: "Safe test policy enforcement."
    },
    {
      id: "soc-gates",
      label: "SOC Gates",
      summary: "High-scale policies remain request-only for customers.",
      evidence: "Authorization and SOC decision artifacts."
    }
  ],
  runs: [
    {
      id: "summary",
      label: "Summary",
      summary: "Current verdict, target group, check family, and guardrail state.",
      evidence: "Run record and policy snapshot."
    },
    {
      id: "timeline",
      label: "Timeline",
      summary: "Ordered run lifecycle from scheduling through final verdict.",
      evidence: "Run events and audit entries."
    },
    {
      id: "probe-results",
      label: "Probe Results",
      summary: "Outside observations from bounded probes.",
      evidence: "Probe result records."
    },
    {
      id: "agent-observations",
      label: "Agent Observations",
      summary: "Inside observations from outbound-only canaries.",
      evidence: "Agent observation records."
    },
    {
      id: "correlation",
      label: "Correlation",
      summary: "Truth table explaining why the verdict was assigned.",
      evidence: "Observed facts and correlation logic."
    },
    {
      id: "evidence",
      label: "Evidence",
      summary: "Custody-ready artifacts generated by the run.",
      evidence: "Evidence ledger references."
    },
    {
      id: "events",
      label: "Raw Events",
      summary: "Sanitized event envelope review for support and audit.",
      evidence: "Redacted event metadata."
    }
  ],
  findings: [
    {
      id: "open",
      label: "Open",
      summary: "Unresolved gaps with severity and owner.",
      evidence: "Finding records and run evidence."
    },
    {
      id: "target-group",
      label: "By Target Group",
      summary: "Group findings by declared business service.",
      evidence: "Target group mapping."
    },
    {
      id: "vector",
      label: "By Vector",
      summary: "Group findings by vector family and safety class.",
      evidence: "Check catalog and verdict."
    },
    {
      id: "accepted-risk",
      label: "Accepted Risk",
      summary: "Owner-approved exceptions with expiry.",
      evidence: "Accepted-risk artifact and audit entry."
    },
    {
      id: "closed",
      label: "Closed",
      summary: "Resolved findings with closure evidence.",
      evidence: "Retest or explicit closure record."
    },
    {
      id: "sla",
      label: "SLA",
      summary: "Due dates, owner aging, and escalation state.",
      evidence: "Finding timeline."
    }
  ],
  "waf-posture": [
    {
      id: "overview",
      label: "Overview",
      summary: "Vendor mix, criticality, geography, and coverage score.",
      evidence: "WAF posture snapshots and declared assets."
    },
    {
      id: "roadmap",
      label: "Roadmap",
      summary: "Risk-prioritized deployment and validation recommendations.",
      evidence: "Coverage rollups and risk factors."
    },
    {
      id: "assets",
      label: "Assets",
      summary: "Protected assets, rule health, scenario pass rate, and action links.",
      evidence: "Asset records and validation evidence."
    },
    {
      id: "scenarios",
      label: "Scenarios",
      summary: "Safe scenario cadence and product catalog guidance.",
      evidence: "Scenario intake and catalog metadata."
    },
    {
      id: "drift",
      label: "Drift",
      summary: "Drift queue, retest state, and exception context.",
      evidence: "Drift scans and retest records."
    },
    {
      id: "connectors",
      label: "Connectors",
      summary: "Optional read-only connector health and poll summaries.",
      evidence: "Connector metadata only."
    },
    {
      id: "reports",
      label: "Reports",
      summary: "Executive coverage, drift audit, connector health, and board brief.",
      evidence: "Report records and custody preview."
    },
    {
      id: "evidence",
      label: "Evidence",
      summary: "Protected-claim evidence and validation outputs.",
      evidence: "Stored probe or agent observations."
    }
  ],
  "cve-pipeline": [
    {
      id: "intake",
      label: "Intake",
      summary: "CVE feed ingestion and reviewed entries.",
      evidence: "CVE source metadata."
    },
    {
      id: "triage",
      label: "Triage",
      summary: "Severity, exposure, and protected-asset match factors.",
      evidence: "Triage factors and WAF asset links."
    },
    {
      id: "matches",
      label: "Matches",
      summary: "Affected declared assets and confidence.",
      evidence: "Asset match records."
    },
    {
      id: "recommendations",
      label: "Recommendations",
      summary: "Mitigation guidance for WAF and service owners.",
      evidence: "Recommendation record."
    },
    {
      id: "staged",
      label: "Staged",
      summary: "Reviewed changes waiting for approval.",
      evidence: "Approval artifact and change context."
    },
    {
      id: "retests",
      label: "Retests",
      summary: "Safe retest workflow after mitigation.",
      evidence: "Retest result evidence."
    },
    {
      id: "playbooks",
      label: "Playbooks",
      summary: "Multi-vendor playbook approval and closure.",
      evidence: "Playbook decision artifacts."
    }
  ],
  "supply-chain": [
    {
      id: "overview",
      label: "Overview",
      summary: "Digital supply-chain risks and state counts.",
      evidence: "Discovery and supply-chain records."
    },
    {
      id: "dependencies",
      label: "Dependencies",
      summary: "CNAME, redirect, script, vendor, and subdomain dependencies.",
      evidence: "Metadata-only source evidence."
    },
    {
      id: "candidates",
      label: "Candidates",
      summary: "Reviewed risk candidates and confidence.",
      evidence: "Candidate source artifacts."
    },
    {
      id: "phases",
      label: "Phases",
      summary: "Detect-only through governed active-protection states.",
      evidence: "Phase authorization."
    },
    {
      id: "tickets",
      label: "Tickets",
      summary: "Remediation links and owner workflow.",
      evidence: "Action item references."
    },
    {
      id: "custody",
      label: "Custody",
      summary: "Customer custody, accepted risk, and closure.",
      evidence: "Audit and evidence exports."
    }
  ],
  remediation: [
    {
      id: "items",
      label: "Action Items",
      summary: "Finding, CVE, and supply-chain remediation tasks.",
      evidence: "Action item record."
    },
    {
      id: "tickets",
      label: "Ticket Preview",
      summary: "Jira and ServiceNow-safe payload preview.",
      evidence: "Redacted payload metadata."
    },
    {
      id: "siem-soar",
      label: "SIEM/SOAR",
      summary: "Webhook and security operations delivery status.",
      evidence: "Delivery metadata and retry state."
    },
    {
      id: "retests",
      label: "Retests",
      summary: "Evidence-backed closure validation.",
      evidence: "Retest run evidence."
    },
    {
      id: "closure",
      label: "Closure",
      summary: "Resolution, accepted risk, or customer custody.",
      evidence: "Closure decision and audit event."
    }
  ],
  discovery: [
    {
      id: "inbox",
      label: "Inbox",
      summary: "Review candidates before they enter declared scope.",
      evidence: "Discovery source metadata."
    },
    {
      id: "entities",
      label: "Entities",
      summary: "Known entities, ownership, and source confidence.",
      evidence: "Entity records."
    },
    {
      id: "sources",
      label: "Sources",
      summary: "Safe D0-D4 source modes and schedule posture.",
      evidence: "Mode and source records."
    },
    {
      id: "decisions",
      label: "Decisions",
      summary: "Approve, dismiss, or request more context.",
      evidence: "Decision audit trail."
    },
    {
      id: "imports",
      label: "Imports",
      summary: "Approved candidates imported into existing declared groups.",
      evidence: "Import action and target-group reference."
    }
  ],
  "high-scale": [
    {
      id: "request",
      label: "Request Form",
      summary: "Customer submits objective, scope, window, contacts, and confirmation.",
      evidence: "High-scale request record."
    },
    {
      id: "authorization",
      label: "Authorization",
      summary: "Authorization pack with customer, provider, legal, and runbook artifacts.",
      evidence: "Approval artifact ledger."
    },
    {
      id: "soc-review",
      label: "SOC Review",
      summary: "Visible status only for customers; decisions remain staff/SOC-owned.",
      evidence: "SOC decision artifact."
    },
    {
      id: "schedule",
      label: "Schedule",
      summary: "Approved window and provider coordination status.",
      evidence: "SOC schedule record."
    },
    {
      id: "live-run",
      label: "Live Run",
      summary: "Customer-visible status while SOC owns execution controls.",
      evidence: "SOC lifecycle events."
    },
    {
      id: "post-test",
      label: "Post-Test",
      summary: "Closure, report, evidence bundle, and lessons learned.",
      evidence: "Post-test report and custody export."
    }
  ],
  soc: [
    {
      id: "queue",
      label: "Queue",
      summary: "SOC-visible high-scale requests and review status.",
      evidence: "Request and authorization pack."
    },
    {
      id: "review",
      label: "Review",
      summary: "Go/no-go checklist and authorization completeness.",
      evidence: "Approval artifact ledger."
    },
    {
      id: "schedule",
      label: "Schedule",
      summary: "Approved window, contacts, and coordination plan.",
      evidence: "SOC schedule action."
    },
    {
      id: "live-status",
      label: "Live Status",
      summary: "Lifecycle state and kill-switch posture.",
      evidence: "SOC-controlled events."
    },
    {
      id: "closeout",
      label: "Closeout",
      summary: "Post-test report, closure status, and custody.",
      evidence: "Post-test report and audit."
    }
  ],
  reports: [
    {
      id: "builder",
      label: "Builder",
      summary: "Report kind, period, audience, and included evidence.",
      evidence: "Report request."
    },
    {
      id: "executive",
      label: "Executive",
      summary: "Readiness and business-risk summary.",
      evidence: "Readiness score and findings."
    },
    {
      id: "technical",
      label: "Technical",
      summary: "Run details, vectors, and remediation context.",
      evidence: "Run and finding evidence."
    },
    {
      id: "soc",
      label: "SOC",
      summary: "High-scale authorization, schedule, and post-test summary.",
      evidence: "SOC artifacts."
    },
    {
      id: "audit",
      label: "Audit",
      summary: "Custody, controls, and security-relevant action trail.",
      evidence: "Audit entries and evidence ledger."
    },
    {
      id: "custody",
      label: "Custody",
      summary: "Digest references and export manifest.",
      evidence: "Custody manifest."
    },
    {
      id: "waf",
      label: "WAF",
      summary: "Coverage, drift, connector health, and roadmap.",
      evidence: "WAF reports and snapshots."
    }
  ],
  notifications: [
    {
      id: "rules",
      label: "Rules",
      summary: "In-app, email, chat, webhook, and owner routing rules.",
      evidence: "Notification rule records."
    },
    {
      id: "events",
      label: "Events",
      summary: "Recent delivery and event state.",
      evidence: "Notification event records."
    },
    {
      id: "providers",
      label: "Providers",
      summary: "Credential status and configuration evidence.",
      evidence: "Provider metadata."
    },
    {
      id: "retry",
      label: "Retry",
      summary: "Safe retry preview and due-work processing.",
      evidence: "Retry queue metadata."
    },
    {
      id: "dlq",
      label: "DLQ",
      summary: "Dead-letter redrive with redacted output.",
      evidence: "DLQ metadata."
    }
  ],
  audit: [
    {
      id: "tenant-audit",
      label: "Tenant Audit",
      summary: "Tenant-scoped security and custody activity.",
      evidence: "Audit log records."
    },
    {
      id: "filters",
      label: "Filters",
      summary: "Actor, action, object, and time filters.",
      evidence: "Audit query context."
    },
    {
      id: "exports",
      label: "Exports",
      summary: "Auditor-friendly export and report links.",
      evidence: "Custody export references."
    }
  ],
  "release-evidence": [
    {
      id: "attestation",
      label: "Attestation",
      summary: "Staging and production readiness statement.",
      evidence: "Attestation record."
    },
    {
      id: "required",
      label: "Required Evidence",
      summary: "Complete inventory of release evidence kinds.",
      evidence: "Release ledger."
    },
    {
      id: "gaps",
      label: "Gaps",
      summary: "Open launch blockers and accepted exceptions.",
      evidence: "Gap audit."
    },
    {
      id: "bundles",
      label: "Bundles",
      summary: "Evidence bundle coverage and provenance.",
      evidence: "Bundle manifest."
    }
  ],
  settings: [
    {
      id: "organization",
      label: "Organization",
      summary: "Tenant profile, environments, support owner, and residency.",
      evidence: "Tenant record."
    },
    {
      id: "users-roles",
      label: "Users & Roles",
      summary: "User access and permission model.",
      evidence: "Role contracts and audit."
    },
    {
      id: "api-keys",
      label: "API Keys",
      summary: "Service accounts, bootstrap tokens, revoke, and rotate.",
      evidence: "Token and service-account records."
    },
    {
      id: "sso",
      label: "SSO/SAML",
      summary: "Enterprise OIDC/JWKS posture with production-safe defaults.",
      evidence: "Auth configuration."
    },
    {
      id: "notifications",
      label: "Notifications",
      summary: "Default routing and provider links.",
      evidence: "Notification rule records."
    },
    {
      id: "integrations",
      label: "Integrations",
      summary: "Optional connectors and remediation delivery.",
      evidence: "Connector and secret metadata."
    },
    {
      id: "retention",
      label: "Data Retention",
      summary: "Retention days, purge state, and privacy controls.",
      evidence: "Retention policy record."
    },
    {
      id: "audit",
      label: "Audit Log",
      summary: "Settings changes and security-sensitive events.",
      evidence: "Audit trail."
    }
  ],
  admin: [
    {
      id: "overview",
      label: "Overview",
      summary: "Staff metrics, pending sign-ups, approvals, and support posture.",
      evidence: "Internal management API."
    },
    {
      id: "signup-queue",
      label: "Sign-up Queue",
      summary: "Approve, reject, request info, and provision tenant.",
      evidence: "Signup request record."
    },
    {
      id: "tenants",
      label: "Tenants",
      summary: "Tenant lifecycle, status, plan, users, and support actions.",
      evidence: "Tenant detail record."
    },
    {
      id: "approvals",
      label: "Approvals",
      summary: "Internal approval queue and decision ledger.",
      evidence: "Approval record."
    },
    {
      id: "audit",
      label: "Internal Audit",
      summary: "Staff actions and management-plane audit.",
      evidence: "Internal audit log."
    }
  ],
  "internal-soc": [
    {
      id: "queue",
      label: "Queue",
      summary: "High-scale requests requiring SOC review.",
      evidence: "Request and authorization pack."
    },
    {
      id: "authorization",
      label: "Authorization",
      summary: "Go/no-go checklist, provider contacts, legal proof, and runbook state.",
      evidence: "Accepted authorization artifacts."
    },
    {
      id: "schedule",
      label: "Schedule",
      summary: "Approved window and coordination state.",
      evidence: "SOC schedule action."
    },
    {
      id: "live-run",
      label: "Live Run",
      summary: "Lifecycle status, notes, telemetry summary, and kill switch.",
      evidence: "SOC-controlled events."
    },
    {
      id: "closeout",
      label: "Closeout",
      summary: "Post-test report, stop state, and closure evidence.",
      evidence: "Post-test report and audit."
    }
  ]
}, gi = {
  "target-group-detail": hi["target-groups"],
  "agent-detail": hi.agents,
  "run-detail": hi.runs,
  "waf-asset-detail": [
    {
      id: "score",
      label: "Score",
      summary: "Asset effectiveness score and risk tier.",
      evidence: "WAF snapshot and validation evidence."
    },
    {
      id: "ruleset",
      label: "Ruleset",
      summary: "Connector rule health and managed-rule posture.",
      evidence: "Connector metadata."
    },
    {
      id: "geo",
      label: "Geo",
      summary: "Geography, region, and business criticality context.",
      evidence: "Declared asset metadata."
    },
    {
      id: "drift",
      label: "Drift",
      summary: "Drift findings and retest status.",
      evidence: "Drift event and retest records."
    },
    {
      id: "exceptions",
      label: "Exceptions",
      summary: "Accepted exceptions and expiry.",
      evidence: "Exception register."
    },
    {
      id: "validation-runs",
      label: "Validation Runs",
      summary: "Safe validation history for the asset.",
      evidence: "Validation plans and run evidence."
    },
    {
      id: "actions",
      label: "Actions",
      summary: "Remediation links and owner next steps.",
      evidence: "Action item records."
    }
  ],
  "discovery-entity": hi.discovery,
  "tenant-detail": hi.admin
};
function _i(e) {
  return hi[e] ?? gi[e] ?? [];
}
//#endregion
//#region apps/web/react/src/components/charts/readiness-gauge.tsx
function vi({ score: e, label: t = "Readiness" }) {
  let n = gn(e), r = 2 * Math.PI * 52, i = r - r * n / 100;
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "readiness-gauge",
    "aria-label": `${t} ${n}`,
    children: [/* @__PURE__ */ (0, R.jsxs)("svg", {
      viewBox: "0 0 140 140",
      role: "img",
      children: [
        /* @__PURE__ */ (0, R.jsx)("circle", {
          className: "gauge-track",
          cx: "70",
          cy: "70",
          r: "52"
        }),
        /* @__PURE__ */ (0, R.jsx)("circle", {
          className: `gauge-fill gauge-fill-${hn(n)}`,
          cx: "70",
          cy: "70",
          r: "52",
          strokeDasharray: r,
          strokeDashoffset: i
        }),
        /* @__PURE__ */ (0, R.jsx)("text", {
          className: "gauge-score",
          x: "70",
          y: "68",
          textAnchor: "middle",
          children: Math.round(n)
        }),
        /* @__PURE__ */ (0, R.jsx)("text", {
          className: "gauge-label",
          x: "70",
          y: "90",
          textAnchor: "middle",
          children: t
        })
      ]
    }), /* @__PURE__ */ (0, R.jsx)(z, {
      tone: hn(n),
      children: n >= 80 ? "Ready" : n >= 55 ? "Needs work" : "At risk"
    })]
  });
}
//#endregion
//#region apps/web/react/src/components/charts/score-trend.tsx
function yi({ runs: e, currentScore: t }) {
  let n = [...e].sort((e, t) => String(e.created_at ?? e.id ?? "").localeCompare(String(t.created_at ?? t.id ?? ""))), r = Number.isFinite(t) ? t : 0, i = n.length ? n.map((e, t) => {
    let i = (t + 1) / n.length;
    return {
      value: Math.round(r * (.5 + .5 * i)),
      label: String(e.id ?? "").slice(-6) || String(t + 1)
    };
  }) : [{
    value: r,
    label: "now"
  }];
  n.length && (i[i.length - 1].value = r);
  let a = Math.max(100, ...i.map((e) => e.value), 1), o = i.map((e, t) => `${4 + t * 192 / Math.max(1, i.length - 1)},${44 - e.value / a * 40}`).join(" ");
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "score-trend",
    role: "img",
    "aria-label": "Readiness score trend",
    children: [/* @__PURE__ */ (0, R.jsxs)("svg", {
      viewBox: "0 0 200 48",
      width: "100%",
      preserveAspectRatio: "none",
      children: [/* @__PURE__ */ (0, R.jsx)("polyline", {
        points: o,
        fill: "none",
        stroke: "currentColor",
        strokeWidth: "2",
        vectorEffect: "non-scaling-stroke"
      }), i.map((e, t) => /* @__PURE__ */ (0, R.jsx)("circle", {
        cx: 4 + t * 192 / Math.max(1, i.length - 1),
        cy: 44 - e.value / a * 40,
        r: "2.5",
        fill: "currentColor"
      }, `${e.label}-${t}`))]
    }), /* @__PURE__ */ (0, R.jsxs)("span", {
      className: "muted score-trend-caption",
      children: [
        i.length,
        " run",
        i.length === 1 ? "" : "s",
        " · current ",
        r
      ]
    })]
  });
}
//#endregion
//#region apps/web/react/src/components/charts/vector-heatmap.tsx
var bi = [
  {
    label: "Origin",
    keys: ["origin"]
  },
  {
    label: "L3/L4",
    keys: [
      "l3_l4",
      "l3/l4",
      "layer_3_4"
    ]
  },
  {
    label: "DNS",
    keys: ["dns"]
  },
  {
    label: "L7/API",
    keys: [
      "l7_api",
      "l7/api",
      "application",
      "api"
    ]
  },
  {
    label: "Protocol",
    keys: [
      "protocol",
      "tls",
      "http2",
      "http3"
    ]
  }
];
function xi(e, t) {
  let n = e[t];
  return n == null ? "" : String(n).toLowerCase();
}
function Si(e, t, n) {
  let r = e[t];
  if (!r || typeof r != "object" || Array.isArray(r)) return "";
  let i = r[n];
  return i == null ? "" : String(i);
}
function Ci(e) {
  return String(e.check_id ?? e.checkId ?? Si(e, "check", "check_id") ?? "");
}
function wi(e) {
  return String(e.target_group_id ?? e.targetGroupId ?? Si(e, "target_group", "id") ?? "");
}
function Ti(e, t) {
  let n = [
    xi(e, "vector_family"),
    xi(e, "category"),
    xi(e, "name"),
    xi(e, "check_id")
  ].join(" ");
  return t.keys.some((e) => n.includes(e));
}
function Ei({ checkIds: e, groupId: t, testPolicies: n, runs: r, evidence: i }) {
  if (!t || e.size === 0) return null;
  let a = n.filter((n) => wi(n) === t && e.has(Ci(n))).length, o = r.filter((n) => wi(n) === t && e.has(Ci(n))).length;
  return i.filter((n) => wi(n) === t && e.has(Ci(n))).length > 0 ? 100 : o > 0 ? 75 : a > 0 ? 50 : 0;
}
function Di({ checks: e, targetGroups: t, testPolicies: n, runs: r, evidence: i }) {
  let a = t.slice(0, 5);
  return a.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
    icon: ke,
    title: "No declared target groups yet.",
    body: "Declare target groups before coverage can be calculated from policies, runs, or evidence."
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "heatmap",
    children: [/* @__PURE__ */ (0, R.jsxs)("div", {
      className: "heatmap-grid",
      style: { gridTemplateColumns: `minmax(132px, 1.1fr) repeat(${bi.length}, minmax(78px, 1fr))` },
      children: [
        /* @__PURE__ */ (0, R.jsx)("span", {
          className: "heatmap-head",
          children: "Target group"
        }),
        bi.map((e) => /* @__PURE__ */ (0, R.jsx)("span", {
          className: "heatmap-head",
          children: e.label
        }, e.label)),
        a.map((t, a) => /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)("strong", {
          className: "heatmap-name",
          children: String(t.name ?? t.id ?? "Declared group")
        }, `${a}-name`), bi.map((o) => {
          let s = String(t.id ?? ""), c = Ei({
            checkIds: new Set(e.filter((e) => Ti(e, o)).map((e) => String(e.check_id ?? e.id ?? "")).filter(Boolean)),
            groupId: s,
            testPolicies: n,
            runs: r,
            evidence: i
          });
          return /* @__PURE__ */ (0, R.jsx)("span", {
            className: `heatmap-cell heatmap-${c === null ? "muted" : c >= 100 ? "success" : c >= 50 ? "warn" : "danger"}`,
            children: c === null ? "n/a" : `${c}%`
          }, `${a}-${o.label}`);
        })] }))
      ]
    }), /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "heatmap-legend",
      children: [
        /* @__PURE__ */ (0, R.jsx)(z, {
          tone: "success",
          children: "Evidence"
        }),
        /* @__PURE__ */ (0, R.jsx)(z, {
          tone: "warn",
          children: "Policy/run"
        }),
        /* @__PURE__ */ (0, R.jsx)(z, {
          tone: "danger",
          children: "No record"
        })
      ]
    })]
  });
}
//#endregion
//#region apps/web/react/src/lib/high-scale.ts
var Oi = [
  "customer_authorization_letter",
  "target_ownership_confirmation",
  "emergency_contacts",
  "stop_criteria",
  "test_plan",
  "business_approval",
  "legal_approval",
  "scope_and_rate_plan",
  "abort_criteria"
], ki = "provider_approval", Ai = Object.fromEntries([
  {
    artifact_type: "customer_authorization_letter",
    title: "Customer Authorization Letter",
    purpose: "Customer confirms that AstraNull SOC is authorized to coordinate the bounded validation.",
    legal_review_required: !0
  },
  {
    artifact_type: "target_ownership_confirmation",
    title: "Target Ownership Confirmation",
    purpose: "Customer confirms declared targets are owned, controlled, or explicitly authorized.",
    legal_review_required: !0
  },
  {
    artifact_type: "emergency_contacts",
    title: "Emergency Contacts",
    purpose: "Defines customer, SOC, and provider stop/escalation contacts during the window."
  },
  {
    artifact_type: "stop_criteria",
    title: "Stop Criteria",
    purpose: "Documents thresholds and authorities that pause or stop the validation."
  },
  {
    artifact_type: "test_plan",
    title: "Test Plan",
    purpose: "Defines scenario families, observations, monitoring, and completion criteria."
  },
  {
    artifact_type: "business_approval",
    title: "Business Approval",
    purpose: "Business owner accepts the timing, risk, communications, and recovery expectations.",
    legal_review_required: !0
  },
  {
    artifact_type: "legal_approval",
    title: "Legal and Policy Approval",
    purpose: "Legal/security owner confirms the validation is authorized under customer and provider rules.",
    legal_review_required: !0
  },
  {
    artifact_type: "scope_and_rate_plan",
    title: "Scope and Rate Plan",
    purpose: "Locks target scope, rate labels, duration caps, and change-control boundaries.",
    legal_review_required: !0
  },
  {
    artifact_type: "abort_criteria",
    title: "Abort Criteria",
    purpose: "Documents immediate abort conditions, customer/provider authority, and recovery steps."
  },
  {
    artifact_type: "provider_approval",
    title: "Provider Approval",
    purpose: "Captures cloud, CDN, carrier, partner, or lab approval metadata without requiring credentials.",
    legal_review_required: !0
  }
].map((e) => [e.artifact_type, e]));
function ji(e) {
  return Ai[e]?.title ?? e.replace(/_/g, " ");
}
function Mi(e) {
  return Ai[e]?.purpose ?? "Authorization metadata reference.";
}
function Ni(e) {
  if (!e) return !1;
  let t = e.provider_context;
  if (!t || typeof t != "object" || Array.isArray(t)) return !1;
  let n = t;
  return n.requires_provider_approval === !0 ? !0 : String(n.provider_name ?? n.provider ?? n.name ?? "").trim().length > 0;
}
function Pi(e) {
  let t = [...Oi];
  return Ni(e) && t.push(ki), t;
}
function Fi(e) {
  if (!e || !Array.isArray(e.audit_trail)) return [];
  let t = [];
  for (let n of e.audit_trail) {
    if (!n || typeof n != "object" || Array.isArray(n)) continue;
    let e = n, r = String(e.action ?? "").trim(), i = String(e.at ?? e.created_at ?? "").trim();
    if (!r || !i) continue;
    let a = e.metadata && typeof e.metadata == "object" && !Array.isArray(e.metadata) ? e.metadata : void 0;
    t.push({
      action: r,
      at: i,
      by: String(e.by ?? "system"),
      ...a ? { metadata: a } : {}
    });
  }
  return t.sort((e, t) => new Date(e.at).getTime() - new Date(t.at).getTime());
}
function Ii(e, t) {
  let n = e.filter((e) => String(e.type ?? "") === t), r = n.find((e) => String(e.status ?? "") === "accepted");
  if (r) return r;
  let i = n.find((e) => String(e.status ?? "") === "pending_review");
  if (i) return i;
  let a = n.filter((e) => String(e.status ?? "") === "rejected");
  return a[a.length - 1] ?? null;
}
function Li(e, t) {
  return (Array.isArray(e?.requirements) ? e.requirements : []).find((e) => String(e.type ?? "") === t) ?? null;
}
function Ri(e) {
  return e ? String(e.status ?? "pending_review") : "missing";
}
function zi(e, t, n) {
  let r = String(t?.status ?? "missing"), i = Ri(n), a = Array.isArray(t?.missing_fields) ? t.missing_fields.map((e) => String(e)) : [];
  if (r === "missing" && !n) return `No ${ji(e)} metadata uploaded yet. SOC cannot review this artifact until a metadata reference is submitted.`;
  if (r === "expired") return `${ji(e)} was accepted but its valid window has expired. Upload refreshed metadata before SOC can approve the pack.`;
  if (r === "rejected" || i === "rejected") {
    let t = n?.review_notes == null ? "" : String(n.review_notes);
    return t ? `SOC rejected ${ji(e)}: ${t}` : `SOC rejected ${ji(e)}. Upload corrected metadata and wait for SOC re-review.`;
  }
  if (r === "partial" || a.length > 0) {
    let t = a.length > 0 ? a.join(", ") : "required proof fields";
    return `${ji(e)} is uploaded but still missing ${t}.`;
  }
  if (r === "pending_review" || i === "pending_review") return `${ji(e)} metadata is uploaded and awaiting SOC review.`;
  if (r === "accepted" && i === "accepted") {
    let r = n?.reviewed_at == null ? t?.reviewed_at == null ? "" : String(t.reviewed_at) : String(n.reviewed_at);
    return r ? `SOC accepted ${ji(e)} on ${r}.` : `SOC accepted ${ji(e)}.`;
  }
  return `${ji(e)} pack status is ${r}; artifact review state is ${i}.`;
}
function Bi() {
  return {
    window_start: (/* @__PURE__ */ new Date(Date.now() - 6e4)).toISOString(),
    window_end: new Date(Date.now() + 36e5).toISOString()
  };
}
function Vi(e, t, n) {
  let r = String(e.id ?? "").trim(), i = String(e.target_group_id ?? "").trim(), a = e.requested_window && typeof e.requested_window == "object" && !Array.isArray(e.requested_window) ? e.requested_window : {}, o = e.requested_limits && typeof e.requested_limits == "object" && !Array.isArray(e.requested_limits) ? e.requested_limits : {}, s = e.provider_context && typeof e.provider_context == "object" && !Array.isArray(e.provider_context) ? e.provider_context : {}, c = Array.isArray(e.requested_scenario_families) ? e.requested_scenario_families.map((e) => String(e)) : ["volumetric_metadata"], l = Array.isArray(e.emergency_contacts) ? e.emergency_contacts : [], u = e.abort_criteria && typeof e.abort_criteria == "object" && !Array.isArray(e.abort_criteria) ? e.abort_criteria : {
    threshold: "error_rate_above_5pct",
    auto_stop: !0
  }, d = {
    type: t,
    filename: n.filename,
    content_sha256: n.content_sha256,
    reference_uri: `metadata://high-scale/${t}/${r}`,
    approval_reference: `metadata://${t}/${r}`,
    approver: "customer-declared",
    valid_window: {
      window_start: a.window_start ?? null,
      window_end: a.window_end ?? null
    },
    approved_targets: i ? [i] : [],
    approved_scenario_families: c,
    max_rate: o.max_rate ?? "metadata-only-cap",
    max_duration_minutes: o.max_duration_minutes ?? 30,
    emergency_contacts: l,
    abort_criteria: u,
    retention_policy: {
      retain_days: 90,
      classification: "governance"
    }
  }, f = String(n.custody_id ?? "").trim();
  f && (d.custody_uri = `custody://${f}`);
  let p = String(s.provider_name ?? s.provider ?? s.name ?? "").trim();
  return t === "provider_approval" && p && (d.provider_name = p), d;
}
//#endregion
//#region apps/web/react/src/lib/dashboard-metrics.ts
function Hi(e, t, n = "") {
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Ui(e) {
  return e.filter((e) => e.archived_at == null).length;
}
function Wi(e) {
  return e.filter((e) => Hi(e, ["status"]) === "online").length;
}
function Gi(e) {
  return e.filter((e) => Hi(e, ["status"], "open") === "open").length;
}
function Ki(e) {
  return e.length;
}
function qi(e) {
  return {
    targetGroups: e.state?.target_groups ?? Ui(e.targetGroups),
    agentsOnline: e.state?.agents_online ?? Wi(e.agents),
    openFindings: e.state?.open_findings ?? Gi(e.findings),
    highScaleRequests: e.state?.high_scale_requests ?? Ki(e.highScale)
  };
}
function Ji(e, t = 5) {
  return [...(Array.isArray(e.state?.recent_runs) ? e.state.recent_runs : null) ?? e.runs].slice(-t).reverse();
}
//#endregion
//#region apps/web/react/src/lib/environments.ts
var Yi = /* @__PURE__ */ new Set(["completed", "verdicted"]);
function Xi(e, t, n = "") {
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Zi(e) {
  return e.archived_at == null;
}
function Qi(e) {
  return [...e.targetGroups.filter(Zi).reduce((e, t) => {
    let n = Xi(t, ["environment_id"], "unassigned"), r = e.get(n) ?? {
      id: n,
      groups: []
    };
    return r.groups.push(t), e.set(n, r), e;
  }, /* @__PURE__ */ new Map()).values()].map((t) => {
    let n = new Set(t.groups.map((e) => Xi(e, ["id"], ""))), r = e.runs.filter((e) => {
      let t = Xi(e, ["status"], "");
      return n.has(Xi(e, ["target_group_id"], "")) && Yi.has(t);
    }).length, i = t.groups.filter((t) => {
      let n = Xi(t, ["id"], "");
      return e.runs.some((e) => Xi(e, ["target_group_id"], "") === n && Yi.has(Xi(e, ["status"], "")));
    }).length, a = e.findings.filter((e) => n.has(Xi(e, ["target_group_id"], "")) && Xi(e, ["status"], "open") === "open").length, o = t.groups.length ? Math.round(i / t.groups.length * 100) : 0, s = o === 100 && a === 0 ? "covered" : o > 0 ? "partial evidence" : "needs evidence";
    return {
      ...t,
      completedRuns: r,
      groupsWithEvidence: i,
      openFindings: a,
      coverage: o,
      state: s
    };
  }).sort((e, t) => e.id.localeCompare(t.id));
}
//#endregion
//#region apps/web/react/src/pages/page-components.tsx
function Y(e, t, n = "—") {
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function $i(e, t, n = 0) {
  for (let n of t) {
    let t = e[n];
    if (typeof t == "number" && Number.isFinite(t)) return t;
  }
  return n;
}
function ea(e, t, n = 0) {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return typeof r == "number" && Number.isFinite(r) ? r : n;
}
function ta(e, t) {
  let n = e;
  for (let e of t) {
    if (!n || typeof n != "object" || Array.isArray(n)) return null;
    n = n[e];
  }
  return n && typeof n == "object" && !Array.isArray(n) ? n : null;
}
function na(e, t) {
  let n = e;
  for (let e of t) {
    if (!n || typeof n != "object" || Array.isArray(n)) return [];
    n = n[e];
  }
  return Array.isArray(n) ? n : [];
}
function ra(e, t, n = "—") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
function ia({ route: e, eyebrow: t }) {
  let n = Wn.get(e);
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: "page-head",
    children: /* @__PURE__ */ (0, R.jsxs)("div", { children: [
      /* @__PURE__ */ (0, R.jsx)("p", {
        className: "eyebrow",
        children: t ?? n?.group
      }),
      /* @__PURE__ */ (0, R.jsx)("h2", { children: n?.label }),
      /* @__PURE__ */ (0, R.jsx)("p", { children: n?.description })
    ] })
  });
}
function X({ label: e, value: t, sub: n, icon: r, tone: i = "default" }) {
  return /* @__PURE__ */ (0, R.jsxs)(H, {
    className: "metric-card",
    children: [
      /* @__PURE__ */ (0, R.jsx)("div", {
        className: "metric-icon",
        children: /* @__PURE__ */ (0, R.jsx)(r, { size: 18 })
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", { children: [
        /* @__PURE__ */ (0, R.jsx)("span", { children: e }),
        /* @__PURE__ */ (0, R.jsx)("strong", { children: t }),
        /* @__PURE__ */ (0, R.jsx)("p", { children: n })
      ] }),
      /* @__PURE__ */ (0, R.jsx)(z, {
        tone: i,
        children: i === "default" ? "live" : i
      })
    ]
  });
}
function aa() {
  return /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Product guardrails" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Every workflow in this UI keeps the defensive validation rules visible." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
    className: "rule-grid",
    children: Jn.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "rule",
      children: [/* @__PURE__ */ (0, R.jsx)(k, { size: 17 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.title }), /* @__PURE__ */ (0, R.jsx)("p", { children: e.body })] })]
    }, e.title))
  })] });
}
function oa(e, t) {
  return e.agents.filter((e) => Y(e, ["target_group_id"]) === t);
}
function sa(e) {
  return e.targetGroups.filter((e) => e.archived_at == null).map((t) => {
    let n = Y(t, ["id"], ""), r = oa(e, n), i = r.filter((e) => Y(e, ["status"]) === "online").length, a = e.findings.filter((e) => Y(e, ["target_group_id"]) === n && Y(e, ["status"], "open") === "open").length, o = e.runs.filter((e) => Y(e, ["target_group_id"]) === n && ["completed", "verdicted"].includes(Y(e, ["status"]))).length;
    return {
      group: t,
      groupId: n,
      boundAgents: r.length,
      onlineAgents: i,
      openFindings: a,
      completedRuns: o
    };
  });
}
function ca(e, t = 10) {
  let n = e.audit.filter((e) => {
    let t = Y(e, ["action", "event_type"]).toLowerCase();
    return t.includes("evidence") || t.includes("custody") || t.includes("export");
  }).map((e) => ({
    id: Y(e, ["id"], ""),
    kind: Y(e, ["action", "event_type"], "audit"),
    created_at: e.created_at ?? e.timestamp,
    source: "audit"
  }));
  return [...[...e.evidence].map((e) => ({
    id: Y(e, ["id"], ""),
    kind: Y(e, ["kind", "type"], "evidence"),
    created_at: e.created_at,
    source: "evidence"
  })), ...n].sort((e, t) => String(t.created_at ?? "").localeCompare(String(e.created_at ?? ""))).slice(0, t);
}
function la({ data: e }) {
  let [t, n] = (0, C.useState)("overview"), r = _i("dashboard").map((e) => ({
    id: e.id,
    label: e.label
  })), i = typeof e.state?.readiness?.score == "number" ? e.state.readiness.score : null, a = Array.isArray(e.state?.readiness?.factors) ? e.state.readiness.factors : [], o = qi(e), s = Ji(e), c = e.findings.filter((e) => Y(e, ["status"], "open") === "open").slice(0, 5), l = [...e.findings].filter((e) => Y(e, ["status"], "open") === "open").sort((e, t) => String(e.created_at ?? e.id ?? "").localeCompare(String(t.created_at ?? t.id ?? ""))).slice(0, 8), u = [...e.evidence].slice(-5).reverse(), d = ca(e), f = sa(e), p = e.highScale.filter((e) => [
    "submitted",
    "under_review",
    "approved",
    "scheduled"
  ].includes(Y(e, ["state"]))).slice(0, 5);
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "dashboard",
        eyebrow: "Readiness command center"
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: t,
        options: r,
        onChange: n,
        className: "tabs-wrap"
      }),
      t === "overview" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "dashboard-grid",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, {
            className: "score-card",
            children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Readiness score" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Evidence-backed score across declared targets." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: i === null ? /* @__PURE__ */ (0, R.jsx)(q, {
              icon: O,
              title: "Readiness state unavailable.",
              body: "The dashboard is waiting for `/v1/state` to return an evidence-backed readiness score."
            }) : /* @__PURE__ */ (0, R.jsx)(vi, { score: i }) })]
          }), /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "metric-grid",
            children: [
              /* @__PURE__ */ (0, R.jsx)(X, {
                label: "Target groups",
                value: o.targetGroups,
                sub: "Customer-declared scope",
                icon: ke,
                tone: "info"
              }),
              /* @__PURE__ */ (0, R.jsx)(X, {
                label: "Agents online",
                value: o.agentsOnline,
                sub: "Outbound-only observers",
                icon: re,
                tone: "success"
              }),
              /* @__PURE__ */ (0, R.jsx)(X, {
                label: "Open findings",
                value: o.openFindings,
                sub: "Evidence-backed gaps",
                icon: Ae,
                tone: o.openFindings > 0 ? "warn" : "success"
              }),
              /* @__PURE__ */ (0, R.jsx)(X, {
                label: "High-scale",
                value: o.highScaleRequests,
                sub: "SOC-gated requests",
                icon: N,
                tone: "muted"
              })
            ]
          })]
        }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Weighted factors" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "No factor can pass without supporting evidence." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
            className: "factor-list",
            children: a.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
              icon: j,
              title: "No readiness factors returned.",
              body: "Factors appear after `/v1/state` publishes evidence-backed scoring inputs."
            }) : a.map((e) => {
              let t = Math.round(e.score ?? 0);
              return /* @__PURE__ */ (0, R.jsxs)("div", {
                className: "factor",
                children: [
                  /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.label ?? e.key }), /* @__PURE__ */ (0, R.jsx)("span", { children: e.reason ?? e.detail ?? "Awaiting evidence." })] }),
                  /* @__PURE__ */ (0, R.jsxs)(z, {
                    tone: hn(t),
                    children: [t, "%"]
                  }),
                  /* @__PURE__ */ (0, R.jsx)(Or, { value: t })
                ]
              }, e.key ?? e.label);
            })
          })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Vector coverage matrix" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Coverage by vector family and declared target group." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(Di, {
            checks: e.checks,
            targetGroups: e.targetGroups,
            testPolicies: e.testPolicies,
            runs: e.runs,
            evidence: e.evidence
          }) })] })]
        }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Recent test runs" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Latest bounded validation activity with links to run detail." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: s.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: pe,
            title: "No test runs yet.",
            body: "Start a safe validation from Onboarding or Test Runs.",
            actionLabel: "Open onboarding",
            actionHref: "#onboarding"
          }) : /* @__PURE__ */ (0, R.jsx)("ul", {
            className: "dashboard-link-list",
            children: s.map((e) => {
              let t = Y(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: t }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
                Y(e, ["status"]),
                " · ",
                Y(e, ["check_id"])
              ] })] }), /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: Mr("run-detail", t),
                children: "Open"
              })] }, t);
            })
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Open findings" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Evidence-backed gaps that still need triage or remediation." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: c.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: Ae,
            title: "No open findings.",
            body: "Findings appear after validation runs produce evidence-backed gaps.",
            actionLabel: "Open findings",
            actionHref: "#findings"
          }) : /* @__PURE__ */ (0, R.jsx)("ul", {
            className: "dashboard-link-list",
            children: c.map((e) => {
              let t = Y(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: Y(e, ["title", "id"]) }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
                Y(e, ["severity"]),
                " · ",
                Y(e, ["assignee"], "unassigned")
              ] })] }), /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#findings",
                children: "Triage"
              })] }, t);
            })
          }) })] })]
        }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Recent evidence" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Latest vault records correlated to runs and findings." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: u.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No evidence records yet.",
            body: "Evidence appears after validation runs complete and observations are correlated.",
            actionLabel: "Open evidence",
            actionHref: "#evidence"
          }) : /* @__PURE__ */ (0, R.jsx)("ul", {
            className: "dashboard-link-list",
            children: u.map((e) => {
              let t = Y(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: t }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
                Y(e, ["kind", "type"]),
                " · ",
                I(e.created_at)
              ] })] }), /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#evidence",
                children: "Inspect"
              })] }, t);
            })
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "High-scale / SOC requests" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Customers submit requests only — SOC executes after approval." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: p.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: N,
            title: "No pending high-scale requests.",
            body: "Governed high-scale intake appears after customers submit authorization packs.",
            actionLabel: "Open high-scale",
            actionHref: "#high-scale"
          }) : /* @__PURE__ */ (0, R.jsx)("ul", {
            className: "dashboard-link-list",
            children: p.map((e) => {
              let t = Y(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: t }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
                Y(e, ["state"]),
                " · ",
                Y(e, ["target_group_id"])
              ] })] }), /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#high-scale",
                children: "View"
              })] }, t);
            })
          }) })] })]
        }),
        /* @__PURE__ */ (0, R.jsx)(aa, {})
      ] }) : null,
      t === "business-services" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Business services" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Declared target groups mapped to environment, owner, and current validation posture." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "name",
            label: "Service",
            render: (e) => Y(e.group, ["name", "id"])
          },
          {
            key: "environment",
            label: "Environment",
            render: (e) => Y(e.group, ["environment_id"], "unassigned")
          },
          {
            key: "owner",
            label: "Owner",
            render: (e) => Y(e.group, ["owner", "owner_email"], "unassigned")
          },
          {
            key: "agents",
            label: "Agents",
            render: (e) => `${e.onlineAgents}/${e.boundAgents} online`
          },
          {
            key: "runs",
            label: "Runs",
            render: (e) => String(e.completedRuns)
          },
          {
            key: "findings",
            label: "Open findings",
            render: (e) => String(e.openFindings)
          },
          {
            key: "actions",
            label: "",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "secondary",
              href: Mr("target-group-detail", e.groupId),
              children: "Open"
            })
          }
        ],
        items: f,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: ke,
          title: "No declared target groups yet.",
          body: "Create a target group to map business services to validation scope.",
          actionLabel: "Open target groups",
          actionHref: "#target-groups"
        })
      }) })] }) : null,
      t === "risk-trends" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [
          /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Readiness trend" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Score trajectory derived from bounded validation run history." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: i === null ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: O,
            title: "Readiness score unavailable.",
            body: "Trend appears after `/v1/state` publishes an evidence-backed score."
          }) : /* @__PURE__ */ (0, R.jsx)(yi, {
            runs: e.runs,
            currentScore: i
          }) })] }),
          /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Vector coverage matrix" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Coverage by vector family and declared target group." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(Di, {
            checks: e.checks,
            targetGroups: e.targetGroups,
            testPolicies: e.testPolicies,
            runs: e.runs,
            evidence: e.evidence
          }) })] }),
          /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Aging open findings" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Oldest open gaps that still pressure readiness." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: l.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: Ae,
            title: "No open findings.",
            body: "Open findings appear after validation runs produce evidence-backed gaps.",
            actionLabel: "Open findings",
            actionHref: "#findings"
          }) : /* @__PURE__ */ (0, R.jsx)("ul", {
            className: "dashboard-link-list",
            children: l.map((e) => {
              let t = Y(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: Y(e, ["title", "id"]) }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
                Y(e, ["severity"]),
                " · opened ",
                I(e.created_at)
              ] })] }), /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#findings",
                children: "Triage"
              })] }, t);
            })
          }) })] })
        ]
      }) : null,
      t === "evidence-feed" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Evidence feed" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Newest evidence vault records and custody-related audit activity." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: d.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
        icon: j,
        title: "No evidence or custody activity yet.",
        body: "Evidence and custody events appear after validation runs complete and exports are verified.",
        actionLabel: "Open evidence",
        actionHref: "#evidence"
      }) : /* @__PURE__ */ (0, R.jsx)("ul", {
        className: "dashboard-link-list",
        children: d.map((e) => /* @__PURE__ */ (0, R.jsxs)("li", { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.id }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
          e.kind,
          " · ",
          e.source,
          " · ",
          I(e.created_at)
        ] })] }), /* @__PURE__ */ (0, R.jsx)(V, {
          size: "sm",
          variant: "secondary",
          href: e.source === "audit" ? "#audit" : "#evidence",
          children: "Inspect"
        })] }, `${e.source}-${e.id}`))
      }) })] }) : null
    ]
  });
}
function ua({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(!1), [m, h] = (0, C.useState)(null), [g, _] = (0, C.useState)(null), v = e.targetGroups[0] ?? null, y = Y(v ?? {}, ["first_target_id"], ""), b = e.checks.find((e) => Y(e, ["safety_class"]) === "safe") ?? e.checks[0] ?? null, x = ni(e.state?.readiness), S = g ?? e.agents, w = ti(S, { pollStartedAt: m ?? void 0 }), T = ri(w.agents[0] ?? S[0] ?? null, x), E = ii(e.runs), D = f || S.some((e) => ei(e)), O = [
    ["Environment", e.targetGroups.length > 0],
    ["Target group", e.targetGroups.length > 0],
    ["Bootstrap token", e.bootstrapTokens.length > 0 || !!u],
    ["Agent heartbeat", D],
    ["Placement test", E],
    ["First safe run", e.runs.some((e) => Y(e, ["check_id"]) !== "path.protected_canary.safe" && [
      "completed",
      "verdicted",
      "running"
    ].includes(Y(e, ["status"])))]
  ], ee = !!(u || e.bootstrapTokens.length > 0) && !f && w.status !== "online" && w.status !== "timeout";
  (0, C.useEffect)(() => {
    if (!ee) return;
    let e = m ?? Date.now();
    m === null && h(e);
    async function i() {
      try {
        let i = await L(t, n, "/v1/agents"), a = Array.isArray(i.items) ? i.items : [];
        _(a);
        let o = ti(a, { pollStartedAt: e });
        (o.status === "online" || o.status === "timeout") && await r();
      } catch {}
    }
    i();
    let a = window.setInterval(() => {
      i();
    }, Qr);
    return () => window.clearInterval(a);
  }, [
    t,
    n,
    r,
    m,
    ee
  ]);
  async function te(e, t, n) {
    a(e), l(""), s("");
    try {
      let e = await t();
      return s(n), await r(), e;
    } catch (e) {
      let t = e.payload;
      return l(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Onboarding action failed.")), null;
    } finally {
      a("");
    }
  }
  async function ne(e) {
    e.preventDefault();
    let r = new FormData(e.currentTarget);
    await te("onboard-create-group", async () => {
      let e = await L(t, n, "/v1/target-groups", {
        method: "POST",
        body: {
          name: String(r.get("name") ?? "Onboarding group").trim(),
          environment_id: String(r.get("environment_id") ?? "env_onboarding").trim(),
          expected_behavior_default: "must_block_before_origin",
          timezone: "UTC"
        }
      }), i = Y(e, ["id"], "");
      return String(r.get("target_value") ?? "").trim() && await L(t, n, `/v1/target-groups/${i}/targets`, {
        method: "POST",
        body: {
          kind: "fqdn",
          value: String(r.get("target_value") ?? "").trim(),
          expected_behavior: "must_block_before_origin"
        }
      }), e;
    }, "Declared target group and optional first target created.") && e.currentTarget.reset();
  }
  async function re() {
    let e = await te("onboard-create-token", () => L(t, n, "/v1/bootstrap-tokens", {
      method: "POST",
      body: {
        name: "onboarding-install",
        environment_id: Y(v, ["environment_id"], "env_demo"),
        ...Y(v, ["id"], "") ? { target_group_id: Y(v, ["id"], "") } : {},
        expires_at: new Date(Date.now() + 3600 * 1e3).toISOString(),
        max_registrations: 1
      }
    }), "Bootstrap token created. Copy the one-time secret now."), r = Y(e, ["secret"], ra(e, ["token", "secret"], ""));
    r && d(r);
  }
  async function ie(e) {
    let r = y;
    if (!r) {
      let i = await L(t, n, `/v1/target-groups/${e}`);
      r = Y((Array.isArray(i.targets) ? i.targets : [])[0] ?? {}, ["id"], "");
    }
    return r;
  }
  async function ae() {
    let e = Y(v, ["id"], ""), r = Y(b ?? {}, ["check_id"], "");
    if (!e || !r) {
      l("Create a target group and ensure a safe check exists before starting a run.");
      return;
    }
    let i = await ie(e);
    if (!i) {
      l("Add at least one declared target before starting a safe validation run.");
      return;
    }
    await te("onboard-start-run", () => L(t, n, "/v1/test-runs", {
      method: "POST",
      body: {
        target_group_id: e,
        target_id: i,
        check_id: r
      }
    }), "Safe validation run started from onboarding.");
  }
  async function oe() {
    let e = Y(v, ["id"], "");
    if (!e) {
      l("Create a target group before starting the placement test.");
      return;
    }
    let r = await ie(e);
    if (!r) {
      l("Add at least one declared target before starting the placement test.");
      return;
    }
    await te("onboard-start-placement-test", () => L(t, n, "/v1/test-runs", {
      method: "POST",
      body: {
        target_group_id: e,
        target_id: r,
        check_id: $r
      }
    }), "Placement test run started — inspect observations on Test Runs when complete.");
  }
  let A = u || "<BOOTSTRAP_TOKEN>", se = Math.floor((w.elapsedMs ?? 0) / 1e3);
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "onboarding",
        eyebrow: "Guided setup"
      }),
      (o || c) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c ? "form-banner error" : "form-banner",
        children: c || o
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "First validation path" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "One environment, one target group, one outbound agent, one bounded validation run." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
        className: "step-grid",
        children: O.map(([e, t], n) => /* @__PURE__ */ (0, R.jsxs)("div", {
          className: t ? "step-card done" : "step-card",
          children: [
            /* @__PURE__ */ (0, R.jsx)("span", { children: t ? /* @__PURE__ */ (0, R.jsx)(k, { size: 16 }) : n + 1 }),
            /* @__PURE__ */ (0, R.jsx)("strong", { children: e }),
            /* @__PURE__ */ (0, R.jsx)("p", { children: t ? "Evidence present" : "Needs setup" })
          ]
        }, e))
      })] }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create declared scope" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Step 1: create the first target group and optional FQDN target." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: ne,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Group name" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "name",
              defaultValue: "Onboarding origin group",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environment ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "environment_id",
              defaultValue: "env_onboarding",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "First target (optional)" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "target_value",
                placeholder: "origin.example.com"
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: i !== "",
                children: "Create target group"
              })
            })
          ]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Bootstrap token and safe run" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Step 2–3: issue install token, then start the first bounded validation run." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "product-form",
          children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              disabled: i !== "",
              onClick: () => void re(),
              children: "Create bootstrap token"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              variant: "secondary",
              disabled: i !== "" || !v || !b,
              onClick: () => void ae(),
              children: "Start safe validation run"
            }),
            /* @__PURE__ */ (0, R.jsx)("pre", {
              className: "codeblock",
              children: `curl -fsSL ${typeof window < "u" ? window.location.origin : ""}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${typeof window < "u" ? window.location.origin : ""}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${A}" bash`
            }),
            u ? /* @__PURE__ */ (0, R.jsx)("p", {
              className: "muted",
              children: "One-time token shown. It will not be displayed again after refresh."
            }) : null
          ]
        })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent heartbeat verification" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Polls ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents" }),
        " every ",
        Qr / 1e3,
        "s after a bootstrap token is issued."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: w.status === "online" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "onboarding-heartbeat-panel onboarding-heartbeat-panel--online",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("p", {
            className: "onboarding-heartbeat-status onboarding-heartbeat-status--online",
            children: [
              "Agent online — last heartbeat ",
              Y(w.agents[0] ?? {}, ["last_heartbeat_at"], "received"),
              "."
            ]
          }),
          /* @__PURE__ */ (0, R.jsxs)("p", {
            className: "muted onboarding-placement-hint",
            children: [
              /* @__PURE__ */ (0, R.jsx)("strong", { children: "Placement confidence:" }),
              " ",
              T
            ]
          }),
          /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "Proceed to the optional placement test or start the first safe validation."
          })
        ]
      }) : w.status === "timeout" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "onboarding-heartbeat-panel onboarding-heartbeat-panel--timeout",
        children: [/* @__PURE__ */ (0, R.jsx)(q, {
          icon: ce,
          title: "Heartbeat timeout reached.",
          body: "No fresh agent heartbeat was observed within the onboarding window. Continue without an agent or regenerate the bootstrap token."
        }), f ? null : /* @__PURE__ */ (0, R.jsx)("div", {
          className: "form-actions",
          children: /* @__PURE__ */ (0, R.jsx)(B, {
            variant: "secondary",
            disabled: i !== "",
            onClick: () => p(!0),
            children: "Continue without agent"
          })
        })]
      }) : /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "onboarding-heartbeat-panel onboarding-heartbeat-panel--waiting",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("p", {
            className: "onboarding-heartbeat-status onboarding-heartbeat-status--waiting",
            "aria-live": "polite",
            children: [/* @__PURE__ */ (0, R.jsx)("span", {
              className: "onboarding-heartbeat-spinner",
              "aria-hidden": "true"
            }), w.status === "stale" ? "Agent registered but heartbeat is stale — waiting for a fresh heartbeat…" : "Waiting for agent heartbeat…"]
          }),
          /* @__PURE__ */ (0, R.jsxs)("p", {
            className: "muted",
            children: [
              "Polling ",
              /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents" }),
              " every ",
              Qr / 1e3,
              "s (elapsed ",
              se,
              "s)."
            ]
          }),
          /* @__PURE__ */ (0, R.jsxs)("p", {
            className: "muted onboarding-placement-hint",
            children: [
              /* @__PURE__ */ (0, R.jsx)("strong", { children: "Placement confidence:" }),
              " ",
              T
            ]
          }),
          /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "row-actions onboarding-troubleshoot",
            children: [
              /* @__PURE__ */ (0, R.jsx)("span", {
                className: "muted",
                children: "Agent not connecting?"
              }),
              /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#agents",
                children: "Open Agents"
              }),
              /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#settings",
                children: "Regenerate token"
              })
            ]
          })
        ]
      }) })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Placement test" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Runs a bounded protected-path canary check (",
        /* @__PURE__ */ (0, R.jsx)("code", { children: $r }),
        ") — metadata only, no exploit payloads."
      ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "product-form",
        children: [E ? /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted onboarding-placement-done",
          children: "Placement test run started — inspect observations on Test Runs when complete."
        }) : /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)(B, {
          disabled: i !== "" || !v,
          onClick: () => void oe(),
          children: "Start placement test"
        }), /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: "Optional — skip if you will run the first safe validation immediately after heartbeat verification."
        })] }), /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "callout-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "callout info",
              children: [/* @__PURE__ */ (0, R.jsx)(Se, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Install where the agent can observe target traffic." })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "callout warn",
              children: [/* @__PURE__ */ (0, R.jsx)(ce, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Run a safe canary before relying on verdicts." })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "callout",
              children: [/* @__PURE__ */ (0, R.jsx)(j, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Evidence vault records the placement signal." })]
            })
          ]
        })]
      })] })
    ]
  });
}
function da({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(() => Y(e.targetGroups[0] ?? {}, ["id"], "")), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(null), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(""), [m, h] = (0, C.useState)(""), g = [...new Set(e.targetGroups.map((e) => Y(e, ["environment_id"], "")).filter(Boolean))], _ = e.targetGroups.find((e) => Y(e, ["id"], "") === i) ?? e.targetGroups[0] ?? null, v = Y(_ ?? {}, ["id"], i), y = Array.isArray(c?.targets) ? c.targets : [];
  (0, C.useEffect)(() => {
    let t = Y(e.targetGroups[0] ?? {}, ["id"], "");
    !i && t && a(t);
  }, [e.targetGroups, i]), (0, C.useEffect)(() => {
    if (!v) {
      l(null);
      return;
    }
    let e = !1;
    return L(t, n, `/v1/target-groups/${v}`).then((t) => {
      e || l(t);
    }).catch(() => {
      e || l(null);
    }), () => {
      e = !0;
    };
  }, [
    t,
    n,
    v
  ]);
  let b = [
    {
      key: "name",
      label: "Group",
      render: (e) => Y(e, ["name", "id"])
    },
    {
      key: "env",
      label: "Environment",
      render: (e) => Y(e, ["environment_id"])
    },
    {
      key: "behavior",
      label: "Expected behavior",
      render: (e) => vn(Y(e, ["expected_behavior_default"], ""))
    },
    {
      key: "timezone",
      label: "Timezone",
      render: (e) => Y(e, ["timezone"])
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: t === v ? "default" : "secondary",
              onClick: () => a(t),
              children: "Open"
            }),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: Mr("target-group-detail", t),
              children: "Detail"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "danger",
              disabled: u !== "",
              onClick: () => void ee(t),
              children: "Archive target group"
            })
          ]
        });
      }
    }
  ], x = y.find((e) => Y(e, ["id"], "") === o) ?? y[0] ?? null;
  (0, C.useEffect)(() => {
    let e = Y(y[0] ?? {}, ["id"], "");
    !o && e && s(e), o && !y.some((e) => Y(e, ["id"], "") === o) && s(e);
  }, [y, o]);
  let S = [
    {
      key: "kind",
      label: "Type",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Y(e, ["kind"])
      })
    },
    {
      key: "value",
      label: "Target",
      render: (e) => Y(e, ["value"])
    },
    {
      key: "expected",
      label: "Expected behavior",
      render: (e) => vn(Y(e, ["expected_behavior"], ""))
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: t === o ? "default" : "secondary",
            onClick: () => s(t),
            children: "Edit"
          }), /* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "ghost",
            href: Mr("target-group-detail", v),
            children: "Detail"
          })]
        });
      }
    }
  ];
  async function w(e, t, n) {
    d(e), h(""), p("");
    try {
      let e = await t();
      return p(n), await r(), e;
    } catch (e) {
      let t = e.payload;
      return h(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Action failed.")), null;
    } finally {
      d("");
    }
  }
  async function T(e = v) {
    if (!e) return;
    let r = await L(t, n, `/v1/target-groups/${e}`);
    l(r);
  }
  async function E(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), o = String(i.get("name") ?? "").trim();
    if (!o) {
      h("Target group name is required.");
      return;
    }
    let s = await w("create-target-group", () => L(t, n, "/v1/target-groups", {
      method: "POST",
      body: {
        name: o,
        environment_id: String(i.get("environment_id") ?? "prod").trim() || "prod",
        description: String(i.get("description") ?? "").trim(),
        expected_behavior_default: String(i.get("expected_behavior_default") ?? "must_block_before_origin"),
        timezone: String(i.get("timezone") ?? "UTC").trim() || "UTC",
        safety_policy: {
          max_concurrent_runs: Number(i.get("max_concurrent_runs") ?? 1),
          min_seconds_between_runs: Number(i.get("min_seconds_between_runs") ?? 300)
        }
      }
    }), "Target group created from declared customer scope.");
    if (s && typeof s == "object" && "id" in s) {
      let e = String(s.id);
      a(e), r.reset(), await T(e);
    }
  }
  async function D(e) {
    if (e.preventDefault(), !v) {
      h("Create or select a target group before adding a target.");
      return;
    }
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("value") ?? "").trim();
    if (!a) {
      h("Target value is required.");
      return;
    }
    await w(`add-target-${v}`, () => L(t, n, `/v1/target-groups/${v}/targets`, {
      method: "POST",
      body: {
        kind: String(i.get("kind") ?? "fqdn"),
        value: a,
        expected_behavior: String(i.get("expected_behavior") ?? Y(_ ?? {}, ["expected_behavior_default"], "must_block_before_origin"))
      }
    }), "Declared target added to the selected group."), r.reset(), await T(v);
  }
  async function O(e) {
    if (e.preventDefault(), !v) return;
    let r = new FormData(e.currentTarget);
    await w(`patch-target-group-${v}`, () => L(t, n, `/v1/target-groups/${v}`, {
      method: "PATCH",
      body: {
        name: String(r.get("name") ?? Y(_ ?? {}, ["name"])).trim(),
        description: String(r.get("description") ?? "").trim(),
        expected_behavior_default: String(r.get("expected_behavior_default") ?? "must_block_before_origin"),
        timezone: String(r.get("timezone") ?? "UTC").trim() || "UTC"
      }
    }), "Target group settings saved."), await T(v);
  }
  async function ee(e) {
    e && window.confirm("Archive this target group?") && (await w(`archive-target-group-${e}`, () => L(t, n, `/v1/target-groups/${e}`, { method: "DELETE" }), "Target group archived."), i === e && (a(""), l(null)));
  }
  async function te(e) {
    if (e.preventDefault(), !v || !o) {
      h("Select a target before saving changes.");
      return;
    }
    let r = new FormData(e.currentTarget);
    await w(`patch-target-${o}`, () => L(t, n, `/v1/target-groups/${v}/targets/${o}`, {
      method: "PATCH",
      body: {
        kind: String(r.get("kind") ?? "fqdn"),
        value: String(r.get("value") ?? "").trim(),
        expected_behavior: String(r.get("expected_behavior") ?? "must_block_before_origin")
      }
    }), "Declared target updated."), await T(v);
  }
  async function ne(e) {
    !v || !e || window.confirm("Delete this declared target?") && (await w(`delete-target-${e}`, () => L(t, n, `/v1/target-groups/${v}/targets/${e}`, { method: "DELETE" }), "Declared target deleted."), o === e && s(""), await T(v));
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: "target-groups" }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Declared groups",
            value: e.targetGroups.length,
            sub: "Customer-provided scope only",
            icon: ke,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Declared targets",
            value: y.length,
            sub: v ? "Selected group detail" : "Select a group",
            icon: ge,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Environments",
            value: g.length,
            sub: "Derived from target-group records",
            icon: N,
            tone: "muted"
          })
        ]
      }),
      (f || m) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: m ? "form-banner error" : "form-banner",
        children: m || f
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create declared target group" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Customers declare scope manually. AstraNull does not discover inventory automatically." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: E,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "name",
              placeholder: "Retail Checkout - Production",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environment" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "environment_id",
              placeholder: "prod",
              defaultValue: "prod"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Description" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "description",
                rows: 3,
                placeholder: "Business service, owner, and known protection context."
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Expected behavior" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "expected_behavior_default",
              defaultValue: "must_block_before_origin",
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_block_before_origin",
                  children: "Must be blocked before origin"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_allow_baseline_health",
                  children: "Must allow baseline health"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_challenge_or_rate_limit",
                  children: "Must challenge or rate-limit"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_not_expose_direct_ip",
                  children: "Must not expose direct IP"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Timezone" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "timezone",
              defaultValue: "UTC"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Max concurrent runs" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "max_concurrent_runs",
              type: "number",
              min: "1",
              max: "5",
              defaultValue: "1"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Cooldown seconds" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "min_seconds_between_runs",
              type: "number",
              min: "60",
              defaultValue: "300"
            })] }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: u !== "",
                children: u === "create-target-group" ? "Creating..." : "Create group"
              })
            })
          ]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Add declared target" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Add FQDN, URL, IP/port, DNS, or canary targets to the selected group." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: D,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Selected group" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                value: v,
                onChange: (e) => a(e.target.value),
                children: [e.targetGroups.length === 0 ? /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "",
                  children: "No target groups yet"
                }) : null, e.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                  value: Y(e, ["id"]),
                  children: Y(e, ["name", "id"])
                }, Y(e, ["id"])))]
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target type" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "kind",
              defaultValue: "fqdn",
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "fqdn",
                  children: "FQDN"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "url",
                  children: "URL"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "ip_port",
                  children: "IP/Port"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "dns",
                  children: "DNS service"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "canary",
                  children: "Canary endpoint"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Value" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "value",
              placeholder: "checkout.example.com",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Expected behavior" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "expected_behavior",
                defaultValue: Y(_ ?? {}, ["expected_behavior_default"], "must_block_before_origin"),
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_block_before_origin",
                    children: "Must be blocked before origin"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_allow_baseline_health",
                    children: "Must allow baseline health"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_challenge_or_rate_limit",
                    children: "Must challenge or rate-limit"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_not_expose_direct_ip",
                    children: "Must not expose direct IP"
                  })
                ]
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: u !== "" || !v,
                children: "Add target"
              })
            })
          ]
        }) })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Declared target groups" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "All rows are tenant API records. Archived groups are removed from this active list." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
        tone: "info",
        children: [e.targetGroups.length, " active"]
      })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: b,
        items: e.targetGroups,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: ke,
          title: "No target groups declared.",
          body: "Create the first business service or protected zone before running validation."
        })
      }) })] }),
      _ ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Selected group settings" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Patch the declaration without changing any unrelated inventory automatically." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: O,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "name",
              defaultValue: Y(_, ["name"])
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Timezone" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "timezone",
              defaultValue: Y(_, ["timezone"], "UTC")
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Description" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "description",
                rows: 3,
                defaultValue: Y(_, ["description"], "")
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Default expected behavior" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "expected_behavior_default",
                defaultValue: Y(_, ["expected_behavior_default"], "must_block_before_origin"),
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_block_before_origin",
                    children: "Must be blocked before origin"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_allow_baseline_health",
                    children: "Must allow baseline health"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_challenge_or_rate_limit",
                    children: "Must challenge or rate-limit"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_not_expose_direct_ip",
                    children: "Must not expose direct IP"
                  })
                ]
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: u !== "",
                children: "Save settings"
              })
            })
          ]
        }, v) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Declared targets" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Target detail is loaded from `/v1/target-groups/",
          "{id}",
          "`."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
          tone: "success",
          children: [y.length, " targets"]
        })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [/* @__PURE__ */ (0, R.jsx)(J, {
          columns: S,
          items: y,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: ge,
            title: "No targets in this group.",
            body: "Add a declared target before safe validation runs can prove coverage."
          })
        }), x ? /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: te,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target type" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "kind",
              defaultValue: Y(x, ["kind"], "fqdn"),
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "fqdn",
                  children: "FQDN"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "url",
                  children: "URL"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "ip_port",
                  children: "IP/Port"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "dns",
                  children: "DNS service"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "canary",
                  children: "Canary endpoint"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Value" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "value",
                defaultValue: Y(x, ["value"], ""),
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Expected behavior" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "expected_behavior",
                defaultValue: Y(x, ["expected_behavior"], "must_block_before_origin"),
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_block_before_origin",
                    children: "Must be blocked before origin"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_allow_baseline_health",
                    children: "Must allow baseline health"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_challenge_or_rate_limit",
                    children: "Must challenge or rate-limit"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "must_not_expose_direct_ip",
                    children: "Must not expose direct IP"
                  })
                ]
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "form-actions full",
              children: [/* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: u !== "",
                children: "Save target"
              }), /* @__PURE__ */ (0, R.jsx)(B, {
                type: "button",
                variant: "danger",
                disabled: u !== "",
                onClick: () => void ne(o),
                children: "Delete target"
              })]
            })
          ]
        }, o) : null] })] })]
      }) : null
    ]
  });
}
function fa({ route: e, data: t }) {
  let n = e === "high-scale" ? t.highScale : e === "notifications" ? t.notificationRules : e === "audit" ? t.audit : e === "release-evidence" ? t.releaseEvidence : t.runs;
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: e }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "High-scale requests",
            value: t.highScale.length,
            sub: "SOC controls required",
            icon: N,
            tone: "muted"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Release evidence",
            value: t.releaseEvidence.length,
            sub: "Metadata-only inventory",
            icon: le,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Audit entries",
            value: pn(t.audit.length),
            sub: "Security-relevant actions",
            icon: j,
            tone: "success"
          })
        ]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: Wn.get(e)?.label }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Governance actions favor approval artifacts, custody, and fail-closed access boundaries." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "id",
            label: "Record",
            render: (e) => Y(e, [
              "title",
              "name",
              "id"
            ])
          },
          {
            key: "state",
            label: "State",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: Y(e, ["status", "state"], "recorded") === "open" ? "warn" : "muted",
              children: Y(e, ["status", "state"], "recorded")
            })
          },
          {
            key: "owner",
            label: "Owner",
            render: (e) => Y(e, [
              "owner",
              "actor_id",
              "requested_by",
              "created_by"
            ], "AstraNull")
          },
          {
            key: "time",
            label: "Time",
            render: (e) => I(e.created_at ?? e.updated_at)
          }
        ],
        items: n,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: "No governance records yet.",
          body: "Requests, approvals, reports, and audit records appear here after controlled workflow activity."
        })
      }) })] })
    ]
  });
}
function pa(e) {
  let t = new Date(Date.now() + e * 60 * 60 * 1e3), n = (e) => String(e).padStart(2, "0");
  return `${t.getFullYear()}-${n(t.getMonth() + 1)}-${n(t.getDate())}T${n(t.getHours())}:${n(t.getMinutes())}`;
}
function ma(e) {
  let t = String(e ?? "").trim();
  if (!t) return "";
  let n = new Date(t);
  return Number.isNaN(n.getTime()) ? "" : n.toISOString();
}
function ha(e) {
  return String(e ?? "").split(",").map((e) => e.trim()).filter(Boolean);
}
async function ga(e) {
  let t = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(e));
  return [...new Uint8Array(t)].map((e) => e.toString(16).padStart(2, "0")).join("");
}
function _a({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)({}), [f, p] = (0, C.useState)(() => Y(e.highScale[0] ?? {}, ["id"], "")), m = Y(e.targetGroups[0] ?? {}, ["environment_id"], ""), h = e.highScale.find((e) => Y(e, ["id"], "") === f) ?? e.highScale[0] ?? null, g = Array.isArray(h?.artifacts) ? h.artifacts : [], _ = ta(h, ["authorization_pack_status"]), v = na(_, ["requirements"]), y = v.filter((e) => Y(e, ["status"], "") !== "accepted").length, b = Fi(h), x = Pi(h), S = Array.isArray(h?.provider_approval_checklist) ? h.provider_approval_checklist : [], w = [
    {
      key: "objective",
      label: "Request",
      render: (e) => Y(e, [
        "objective",
        "reason",
        "id"
      ])
    },
    {
      key: "state",
      label: "State",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: Y(e, ["state"]) === "submitted" ? "warn" : "info",
        children: Y(e, ["state"])
      })
    },
    {
      key: "target",
      label: "Target group",
      render: (e) => Y(e, ["target_group_id"])
    },
    {
      key: "pack",
      label: "Pack",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: ra(e, ["authorization_pack_status", "overall"]) === "accepted" ? "success" : "warn",
        children: ra(e, ["authorization_pack_status", "overall"], "missing")
      })
    },
    {
      key: "window",
      label: "Window",
      render: (e) => I(ra(e, ["requested_window", "window_start"], ""))
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: "secondary",
          onClick: () => p(t),
          children: "Select"
        });
      }
    }
  ], T = [
    {
      key: "type",
      label: "Type",
      render: (e) => ji(Y(e, ["type"]))
    },
    {
      key: "review",
      label: "Review state",
      render: (e) => {
        let t = Y(e, ["type"]), n = Li(_, t);
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "stack-tight",
          children: [/* @__PURE__ */ (0, R.jsx)(z, {
            tone: Y(e, ["status"]) === "accepted" ? "success" : Y(e, ["status"]) === "rejected" ? "danger" : "warn",
            children: Y(e, ["status"], "pending_review")
          }), /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted small",
            children: zi(t, n, e)
          })]
        });
      }
    },
    {
      key: "filename",
      label: "Filename",
      render: (e) => Y(e, ["filename_redacted", "filename"], "metadata reference")
    },
    {
      key: "digest",
      label: "content_sha256",
      render: (e) => Y(e, ["content_sha256"], "recorded").slice(0, 16)
    },
    {
      key: "custody",
      label: "custody_id",
      render: (e) => Y(e, ["custody_id"], "assigned on upload")
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    }
  ];
  (0, C.useEffect)(() => {
    if (e.highScale.length === 0) {
      f && p("");
      return;
    }
    e.highScale.some((e) => Y(e, ["id"], "") === f) || p(Y(e.highScale[0] ?? {}, ["id"], ""));
  }, [e.highScale, f]);
  async function E(e, t, n) {
    a(e), l(""), s("");
    try {
      let e = await t();
      return s(n), await r(), e;
    } catch (e) {
      let t = e.payload, n = Array.isArray(t?.missing) ? ` Missing: ${t.missing.join(", ")}.` : "";
      return l(`${t?.message ?? t?.error ?? (e instanceof Error ? e.message : "High-scale action failed.")}${n}`), null;
    } finally {
      a("");
    }
  }
  async function D(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = Number(i.get("max_duration_minutes") ?? 45), o = Number(i.get("max_error_rate_pct") ?? 5), s = {
      target_group_id: String(i.get("target_group_id") ?? "").trim(),
      objective: String(i.get("objective") ?? "").trim(),
      environment: String(i.get("environment") ?? "staging").trim(),
      business_criticality: String(i.get("business_criticality") ?? "high").trim(),
      requested_scenario_families: ha(i.get("requested_scenario_families")),
      requested_limits: {
        max_rate: String(i.get("max_rate") ?? "").trim(),
        max_duration_minutes: Number.isFinite(a) && a > 0 ? a : 45
      },
      stop_criteria: {
        abort_on_customer_signal: !0,
        max_error_rate_pct: Number.isFinite(o) && o > 0 ? o : 5
      },
      abort_criteria: {
        threshold: String(i.get("abort_threshold") ?? "error_rate_above_5pct").trim(),
        auto_stop: !0
      },
      requested_window: {
        window_start: ma(i.get("window_start")),
        window_end: ma(i.get("window_end")),
        timezone: String(i.get("timezone") ?? "UTC").trim() || "UTC"
      },
      emergency_contacts: [{
        name: String(i.get("contact_name") ?? "").trim(),
        contact: String(i.get("contact") ?? "").trim()
      }],
      provider_context: {
        provider_name: String(i.get("provider_name") ?? "").trim(),
        requires_provider_approval: i.get("requires_provider_approval") === "on"
      },
      scope_confirmation: i.get("scope_confirmation") === "on"
    }, c = await E("create-high-scale", () => L(t, n, "/v1/high-scale-requests", {
      method: "POST",
      body: s
    }), "High-scale request submitted for SOC review.");
    c && typeof c == "object" && (p(Y(c, ["id"], f)), r.reset());
  }
  function O(e, t, n) {
    d((r) => ({
      ...r,
      [e]: {
        filename: r[e]?.filename ?? "",
        content_sha256: r[e]?.content_sha256 ?? "",
        custody_id: r[e]?.custody_id ?? "",
        [t]: n
      }
    }));
  }
  async function ee(e) {
    if (!h) return;
    let r = Y(h, ["id"], ""), i = u[e] ?? {
      filename: "",
      content_sha256: "",
      custody_id: ""
    }, a = i.filename.trim();
    if (!a) {
      l(`Filename is required for ${ji(e)}.`);
      return;
    }
    let o = i.content_sha256.trim() || await ga(`authorization-artifact:${r}:${e}:${a}`), s = Vi(h, e, {
      filename: a,
      content_sha256: o,
      custody_id: i.custody_id.trim() || void 0
    });
    await E(`upload-artifact-${e}`, () => L(t, n, `/v1/high-scale-requests/${r}/artifacts`, {
      method: "POST",
      body: s
    }), `${ji(e)} metadata uploaded.`) && d((t) => ({
      ...t,
      [e]: {
        filename: "",
        content_sha256: "",
        custody_id: ""
      }
    }));
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "high-scale",
        eyebrow: "SOC-gated validation"
      }),
      e.highScale.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
        icon: N,
        title: "No high-scale requests yet.",
        body: "Submit a governed request with scope confirmation. AstraNull SOC reviews authorization metadata before any execution is scheduled."
      }) : null,
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Requests",
            value: e.highScale.length,
            sub: "Customer-created, SOC-controlled",
            icon: N,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Selected pack",
            value: Y(_ ?? {}, ["overall"], h ? "missing" : "None"),
            sub: `${y} requirements not accepted`,
            icon: j,
            tone: Y(_ ?? {}, ["overall"]) === "accepted" ? "success" : "warn"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Artifacts",
            value: g.length,
            sub: "Metadata-only custody references",
            icon: le,
            tone: "muted"
          })
        ]
      }),
      (o || c) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c ? "form-banner error" : "form-banner",
        children: c || o
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Request governed validation" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Submit authorization metadata for SOC review. Customers cannot approve, schedule, start, stop, or close high-scale execution." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: D,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "target_group_id",
              required: !0,
              defaultValue: Y(e.targetGroups[0] ?? {}, ["id"], ""),
              children: [/* @__PURE__ */ (0, R.jsx)("option", {
                value: "",
                children: "Select declared scope"
              }), e.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: Y(e, ["id"]),
                children: Y(e, ["name", "id"])
              }, Y(e, ["id"])))]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environment" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "environment",
              defaultValue: m,
              placeholder: "staging",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Objective" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "objective",
                rows: 3,
                placeholder: "Describe the governed readiness validation objective.",
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Business criticality" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "business_criticality",
              defaultValue: "high",
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "medium",
                  children: "Medium"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "high",
                  children: "High"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "critical",
                  children: "Critical"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Scenario families" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "requested_scenario_families",
              defaultValue: "volumetric_metadata",
              placeholder: "volumetric_metadata",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Max rate" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "max_rate",
              defaultValue: "500_rps_metadata",
              placeholder: "500_rps_metadata",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Max duration" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "max_duration_minutes",
              type: "number",
              min: "1",
              max: "240",
              defaultValue: "45"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Window start" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "window_start",
              type: "datetime-local",
              defaultValue: pa(24),
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Window end" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "window_end",
              type: "datetime-local",
              defaultValue: pa(48),
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Provider" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "provider_name",
              defaultValue: "Cloudflare",
              placeholder: "Provider name",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Stop threshold" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "max_error_rate_pct",
              type: "number",
              min: "1",
              max: "100",
              defaultValue: "5"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Abort criteria" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "abort_threshold",
              defaultValue: "error_rate_above_5pct",
              placeholder: "error_rate_above_5pct",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Emergency contact" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "contact_name",
              defaultValue: "Primary on-call",
              placeholder: "Primary on-call",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Contact path" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "contact",
              defaultValue: "ops@example.invalid",
              placeholder: "ops@example.com or bridge path",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Timezone" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "timezone",
              defaultValue: "UTC"
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "check-row",
              children: [/* @__PURE__ */ (0, R.jsx)("input", {
                name: "requires_provider_approval",
                type: "checkbox",
                defaultChecked: !0
              }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Provider approval is required." })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "check-row full",
              children: [/* @__PURE__ */ (0, R.jsx)("input", {
                name: "scope_confirmation",
                type: "checkbox",
                defaultChecked: !0,
                required: !0
              }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Declared scope and authorization metadata are accurate." })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: i !== "" || e.targetGroups.length === 0,
                children: i === "create-high-scale" ? "Submitting..." : "Submit high-scale request"
              })
            })
          ]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Authorization pack uploads" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Metadata-only references per required artifact type (`type`, `filename`, `content_sha256`, optional `custody_id`). Raw documents are not uploaded here." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: e.highScale.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
          icon: j,
          title: "No high-scale request selected.",
          body: "Submit a request before uploading authorization artifacts."
        }) : /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "stack",
          children: [/* @__PURE__ */ (0, R.jsxs)("label", {
            className: "full",
            children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Request" }), /* @__PURE__ */ (0, R.jsx)("select", {
              value: f || Y(h ?? {}, ["id"], ""),
              onChange: (e) => p(e.target.value),
              required: !0,
              children: e.highScale.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: Y(e, ["id"]),
                children: Y(e, ["objective", "id"])
              }, Y(e, ["id"])))
            })]
          }), /* @__PURE__ */ (0, R.jsx)("div", {
            className: "artifact-upload-grid",
            children: x.map((e) => {
              let t = Li(_, e), n = Ii(g, e), r = u[e] ?? {
                filename: "",
                content_sha256: "",
                custody_id: ""
              }, a = Y(t ?? {}, ["status"], "missing"), o = a === "accepted" ? "success" : a === "rejected" ? "danger" : "warn";
              return /* @__PURE__ */ (0, R.jsxs)("div", {
                className: "artifact-upload-card",
                children: [
                  /* @__PURE__ */ (0, R.jsxs)("div", {
                    className: "artifact-upload-card__header",
                    children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: ji(e) }), /* @__PURE__ */ (0, R.jsx)("p", {
                      className: "muted small",
                      children: Mi(e)
                    })] }), /* @__PURE__ */ (0, R.jsx)(z, {
                      tone: o,
                      children: a
                    })]
                  }),
                  /* @__PURE__ */ (0, R.jsx)("p", {
                    className: "muted small",
                    children: zi(e, t, n)
                  }),
                  n ? /* @__PURE__ */ (0, R.jsxs)("div", {
                    className: "artifact-upload-card__meta muted small",
                    children: [
                      /* @__PURE__ */ (0, R.jsxs)("div", { children: [
                        /* @__PURE__ */ (0, R.jsx)("strong", { children: "custody_id" }),
                        " ",
                        Y(n, ["custody_id"], "pending")
                      ] }),
                      /* @__PURE__ */ (0, R.jsxs)("div", { children: [
                        /* @__PURE__ */ (0, R.jsx)("strong", { children: "content_sha256" }),
                        " ",
                        Y(n, ["content_sha256"], "recorded").slice(0, 24)
                      ] }),
                      /* @__PURE__ */ (0, R.jsxs)("div", { children: [
                        /* @__PURE__ */ (0, R.jsx)("strong", { children: "filename" }),
                        " ",
                        Y(n, ["filename_redacted", "filename"], "metadata reference")
                      ] })
                    ]
                  }) : null,
                  /* @__PURE__ */ (0, R.jsxs)("div", {
                    className: "product-form compact",
                    children: [
                      /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Artifact type" }), /* @__PURE__ */ (0, R.jsx)("input", {
                        value: e,
                        readOnly: !0,
                        "aria-readonly": "true"
                      })] }),
                      /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Filename" }), /* @__PURE__ */ (0, R.jsx)("input", {
                        value: r.filename,
                        placeholder: `${e}.pdf.metadata`,
                        onChange: (t) => O(e, "filename", t.target.value)
                      })] }),
                      /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Content SHA-256" }), /* @__PURE__ */ (0, R.jsx)("input", {
                        value: r.content_sha256,
                        placeholder: "Auto-computed from metadata when blank",
                        onChange: (t) => O(e, "content_sha256", t.target.value)
                      })] }),
                      /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Custody ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
                        value: r.custody_id,
                        placeholder: n ? Y(n, ["custody_id"], "assigned on upload") : "Optional customer custody reference",
                        onChange: (t) => O(e, "custody_id", t.target.value)
                      })] }),
                      /* @__PURE__ */ (0, R.jsx)("div", {
                        className: "form-actions",
                        children: /* @__PURE__ */ (0, R.jsx)(B, {
                          type: "button",
                          size: "sm",
                          disabled: i !== "",
                          onClick: () => void ee(e),
                          children: i === `upload-artifact-${e}` ? "Uploading..." : "Upload metadata"
                        })
                      })
                    ]
                  })
                ]
              }, e);
            })
          })]
        }) })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "High-scale requests" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Rows are loaded from `/v1/high-scale-requests`; execution stays SOC-only." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
        tone: "info",
        children: [e.highScale.length, " requests"]
      })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: w,
        items: e.highScale,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: "No governed requests.",
          body: "Submit a high-scale request after declaring target scope and authorization metadata."
        })
      }) })] }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Authorization pack status" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Computed by the backend from intake fields, required artifacts, and provider checklist state." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "queue-list",
          children: h ? v.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No requirements returned.",
            body: "The backend did not return authorization pack requirement details yet."
          }) : v.map((e) => {
            let t = Y(e, ["type"]), n = Ii(g, t), r = Y(e, ["status"]);
            return /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "stack-tight",
              children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(z, {
                tone: r === "accepted" ? "success" : r === "rejected" ? "danger" : "warn",
                children: r
              }), /* @__PURE__ */ (0, R.jsx)("span", { children: ji(t) })] }), /* @__PURE__ */ (0, R.jsx)("p", {
                className: "muted small",
                children: zi(t, e, n)
              })]
            }, t);
          }) : /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No request selected.",
            body: "Select or submit a request to inspect authorization requirements."
          })
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Selected request artifacts" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Artifacts are metadata references only; raw documents and payloads are rejected by the API." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: T,
          items: g,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: le,
            title: "No artifacts attached.",
            body: "Upload authorization metadata references for SOC review."
          })
        }) })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Lifecycle timeline" }), /* @__PURE__ */ (0, R.jsx)(G, { children: h ? `Recorded transitions from audit_trail only. Current request state: ${Y(h, ["state"])}.` : "Customer-visible state transitions from audit_trail on the selected request." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: h ? b.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
          icon: ce,
          title: "No lifecycle events yet.",
          body: "State transitions appear after SOC review, scheduling, execution, or closure actions are recorded."
        }) : /* @__PURE__ */ (0, R.jsx)("div", {
          className: "timeline-list",
          children: b.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: t + 1 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [
            /* @__PURE__ */ (0, R.jsx)("strong", { children: e.action }),
            /* @__PURE__ */ (0, R.jsxs)("p", { children: [
              I(e.at),
              " · ",
              e.by
            ] }),
            e.metadata && Object.keys(e.metadata).length > 0 ? /* @__PURE__ */ (0, R.jsxs)("p", {
              className: "muted small",
              children: ["Recorded metadata: ", Object.keys(e.metadata).join(", ")]
            }) : null
          ] })] }, `${e.action}-${e.at}-${t}`))
        }) : /* @__PURE__ */ (0, R.jsx)(q, {
          icon: ce,
          title: "No request selected.",
          body: "Select a governed request to inspect lifecycle history."
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Provider approval checklist" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Provider-specific approval metadata required before SOC can schedule governed execution." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "queue-list",
          children: h ? S.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: N,
            title: "No provider checklist items.",
            body: "Declare provider context on intake or upload a provider_approval artifact to populate checklist state."
          }) : S.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(z, {
            tone: Y(e, ["status"], "") === "approved" ? "success" : "warn",
            children: Y(e, ["status"], "pending")
          }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
            Y(e, ["provider_name"], "provider"),
            " · ",
            Y(e, ["approval_reference"], "no reference")
          ] })] }, Y(e, ["provider_key", "provider_name"], ""))) : /* @__PURE__ */ (0, R.jsx)(q, {
            icon: N,
            title: "No request selected.",
            body: "Provider checklist items are created from intake provider context and approval artifacts."
          })
        })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "SOC handoff (read-only)" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Customers submit requests and authorization metadata here. Approval, scheduling, execution, stop, and close remain on the SOC console — this page does not call `/internal/soc/*` routes." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "row-actions",
        children: [/* @__PURE__ */ (0, R.jsx)(V, {
          href: "#soc",
          variant: "secondary",
          size: "sm",
          children: "Open SOC console"
        }), /* @__PURE__ */ (0, R.jsx)(V, {
          href: "#support",
          variant: "ghost",
          size: "sm",
          children: "Open support readiness"
        })]
      })] })
    ]
  });
}
var va = [
  {
    value: "executive",
    label: "Executive"
  },
  {
    value: "board",
    label: "Board"
  },
  {
    value: "technical",
    label: "Technical"
  },
  {
    value: "soc",
    label: "SOC"
  },
  {
    value: "audit",
    label: "Audit"
  },
  {
    value: "soc2",
    label: "SOC 2"
  },
  {
    value: "iso27001",
    label: "ISO 27001"
  },
  {
    value: "dora",
    label: "DORA"
  },
  {
    value: "nis2",
    label: "NIS2"
  },
  {
    value: "internal_audit",
    label: "Internal audit"
  }
];
function ya({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(null), f = e.reports, p = f[0] ?? null, m = e.audit.filter((e) => Y(e, ["action"], "") === "report.exported").length, h = [
    {
      key: "title",
      label: "Report",
      render: (e) => {
        let t = Y(e, ["id"], ""), n = Y(e, ["title", "id"]);
        return t ? /* @__PURE__ */ (0, R.jsx)(V, {
          size: "sm",
          variant: "ghost",
          href: Mr("report-detail", t),
          children: n
        }) : n;
      }
    },
    {
      key: "kind",
      label: "Kind",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Y(e, ["kind"])
      })
    },
    {
      key: "readiness",
      label: "Readiness",
      render: (e) => `${ea(e, ["summary", "readiness_score"], 0)}%`
    },
    {
      key: "findings",
      label: "Open findings",
      render: (e) => ea(e, ["summary", "open_findings"], 0)
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "secondary",
              href: Mr("report-detail", t),
              children: "Detail"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void v(t, "json"),
              children: "JSON"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void v(t, "markdown"),
              children: "MD"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void v(t, "html"),
              children: "HTML"
            })
          ]
        });
      }
    }
  ];
  async function g(e, t, n) {
    a(e), l(""), s("");
    try {
      let e = await t();
      return s(n), e;
    } catch (e) {
      let t = e.payload;
      return l(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Report action failed.")), null;
    } finally {
      a("");
    }
  }
  async function _(e) {
    e.preventDefault();
    let i = e.currentTarget, a = new FormData(i), o = String(a.get("title") ?? "").trim() || "AstraNull Readiness Summary", s = String(a.get("kind") ?? "technical"), c = await g("create-report", () => L(t, n, "/v1/reports", {
      method: "POST",
      body: {
        title: o,
        kind: s
      }
    }), "Report generated from current workspace data.");
    if (c && typeof c == "object") {
      i.reset(), await r();
      let e = Y(c, ["id"], "");
      e && await v(e, "json");
    }
  }
  async function v(e, i) {
    e && await g(`export-${e}-${i}`, async () => {
      let a = Nn(t, n), o = await fetch(`/v1/reports/${encodeURIComponent(e)}/export?format=${i}`, { headers: a }), s = o.headers.get("content-type") ?? "";
      if (!o.ok) {
        let e = await o.json().catch(() => null);
        throw Error(String(e?.message ?? e?.error ?? `Export returned ${o.status}`));
      }
      if (i === "json" || s.includes("application/json")) {
        let a = await o.json(), s = ta(a, ["custody"]), c = ta(a, ["payload"]), l = null;
        if (s && c) {
          let e = await L(t, n, "/v1/custody/verify", {
            method: "POST",
            body: {
              payload: c,
              custody: s
            }
          });
          l = ta(e, ["verification"]) ?? e;
        }
        return d({
          reportId: e,
          format: i,
          title: ra(c, ["title"], Y(f.find((t) => Y(t, ["id"], "") === e) ?? {}, ["title"], e)),
          contentSha256: Y(s ?? {}, ["content_sha256"], ""),
          artifactId: Y(s ?? {}, ["artifact_id"], ""),
          schemaVersion: Y(s ?? {}, ["schema_version"], ""),
          verification: l
        }), await r(), a;
      }
      let c = await o.text();
      return d({
        reportId: e,
        format: i,
        title: Y(f.find((t) => Y(t, ["id"], "") === e) ?? {}, ["title"], e),
        textPreview: c.slice(0, 900)
      }), await r(), c;
    }, `Report exported as ${i}.`);
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: "reports" }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Reports",
            value: f.length,
            sub: "Generated from tenant evidence",
            icon: le,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Exports",
            value: m,
            sub: "Audit records with custody digests",
            icon: j,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Latest",
            value: p ? Y(p, ["kind"]) : "None",
            sub: p ? I(p.created_at) : "Generate a report first",
            icon: ce,
            tone: p ? "muted" : "warn"
          })
        ]
      }),
      (o || c) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c ? "form-banner error" : "form-banner",
        children: c || o
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Generate report" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Create a tenant-scoped report from current readiness, run, finding, and compliance mapping data." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: _,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Title" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "title",
                placeholder: "Q3 readiness evidence pack"
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Report kind" }), /* @__PURE__ */ (0, R.jsx)("select", {
              name: "kind",
              defaultValue: "technical",
              children: va.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: e.value,
                children: e.label
              }, e.value))
            })] }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: i !== "",
                children: i === "create-report" ? "Generating..." : "Generate report"
              })
            })
          ]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Export custody" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "JSON exports are verified through `/v1/custody/verify`; text exports render a safe preview." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: u ? "kv-list" : "",
          children: u ? u.contentSha256 ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Report" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.title })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Artifact" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.artifactId })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "content_sha256" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.contentSha256 })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Schema" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.schemaVersion })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Verification" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Y(u.verification ?? {}, ["ok"], "verified") })] })
          ] }) : /* @__PURE__ */ (0, R.jsx)("pre", {
            className: "codeblock",
            children: u.textPreview
          }) : /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No export selected.",
            body: "Generate or export a report to inspect custody metadata."
          })
        })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Generated reports" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Rows come from `/v1/reports`; exports call the backend and append custody audit metadata." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
        tone: "info",
        children: [f.length, " records"]
      })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "stack-tight",
        children: [/* @__PURE__ */ (0, R.jsx)(J, {
          columns: h,
          items: f,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: le,
            title: "No reports generated.",
            body: "Generate a report after validation activity to create a custody-ready evidence artifact."
          })
        }), /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: "PDF export is not available in this slice; backend report exports support JSON, Markdown, and HTML only."
        })]
      })] })
    ]
  });
}
function ba(e) {
  let t = Date.now();
  return e === "15m" ? new Date(t + 900 * 1e3).toISOString() : e === "1h" ? new Date(t + 3600 * 1e3).toISOString() : e === "24h" ? new Date(t + 1440 * 60 * 1e3).toISOString() : e === "30d" ? new Date(t + 720 * 60 * 60 * 1e3).toISOString() : null;
}
var xa = [
  {
    id: "organization",
    label: "Organization"
  },
  {
    id: "users",
    label: "Users & roles"
  },
  {
    id: "api-keys",
    label: "API keys"
  },
  {
    id: "sso",
    label: "SSO"
  },
  {
    id: "retention",
    label: "Data retention"
  },
  {
    id: "secrets",
    label: "Secret vault"
  },
  {
    id: "audit",
    label: "Audit log"
  }
];
function Sa(e) {
  let t = e.siteConfig, n = ra(t, ["oidc", "issuer"], "") || Y(t, ["oidc_issuer"], ""), r = ra(t, ["oidc", "audience"], "") || Y(t, ["oidc_audience"], "");
  return {
    authMode: e.authMode,
    issuer: n && n !== "—" ? n : null,
    audience: r && r !== "—" ? r : null,
    bundledStagingLogin: e.bundledLoginEnabled
  };
}
function Ca({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)("organization"), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(null), [m, h] = (0, C.useState)(""), g = e.tenant, _ = ta(g, ["privacy_settings"]) ?? {}, v = ta(_, ["evidence_retention"]) ?? {}, y = $i(_, ["metadata_retention_days"], 90), b = Sa(t), x = {
    principal: n.principal,
    staffRole: n.staff_role
  }, S = n.role ?? "admin", w = tr(S, "audit", x), T = tr(S, "notifications", x), E = tr(S, "release-evidence", x), D = xa.filter((e) => e.id !== "audit" || w), O = [
    {
      key: "name",
      label: "Token",
      render: (e) => Y(e, ["name", "id"])
    },
    {
      key: "environment",
      label: "Environment",
      render: (e) => Y(e, ["environment_id"])
    },
    {
      key: "usage",
      label: "Usage",
      render: (e) => `${$i(e, ["registrations_used"])}/${$i(e, ["max_registrations"], 1)}`
    },
    {
      key: "expires",
      label: "Expires",
      render: (e) => I(e.expires_at)
    },
    {
      key: "state",
      label: "State",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: e.revoked_at ? "muted" : "success",
        children: e.revoked_at ? "revoked" : "active"
      })
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: "danger",
          disabled: o !== "" || !!e.revoked_at,
          onClick: () => void ie(t),
          children: "Revoke"
        });
      }
    }
  ], ee = [
    {
      key: "name",
      label: "Account",
      render: (e) => Y(e, ["name", "id"])
    },
    {
      key: "role",
      label: "Role",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Y(e, ["role"])
      })
    },
    {
      key: "scopes",
      label: "Scopes",
      render: (e) => Array.isArray(e.scopes) ? e.scopes.join(", ") : "role defaults"
    },
    {
      key: "expires",
      label: "Expires",
      render: (e) => e.expires_at ? I(e.expires_at) : "No expiry"
    },
    {
      key: "state",
      label: "State",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: e.revoked_at ? "muted" : "success",
        children: e.revoked_at ? "revoked" : "active"
      })
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            disabled: o !== "" || !!e.revoked_at,
            onClick: () => void oe(t),
            children: "Rotate"
          }), /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "danger",
            disabled: o !== "" || !!e.revoked_at,
            onClick: () => void ae(t),
            children: "Revoke"
          })]
        });
      }
    }
  ];
  async function te(e, t, n) {
    s(e), d(""), l("");
    try {
      let e = await t();
      return l(n), await r(), e;
    } catch (e) {
      let t = e.payload;
      return d(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Action failed.")), null;
    } finally {
      s("");
    }
  }
  async function ne(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("name") ?? "").trim() || "Install token", o = ba(String(i.get("expiry") ?? "1h")), s = Number(i.get("max_registrations") ?? 1), c = String(i.get("target_group_id") ?? "").trim(), l = await te("create-bootstrap-token", () => L(t, n, "/v1/bootstrap-tokens", {
      method: "POST",
      body: {
        name: a,
        environment_id: String(i.get("environment_id") ?? "env_demo"),
        ...c ? { target_group_id: c } : {},
        max_registrations: Number.isFinite(s) && s > 0 ? s : 1,
        ...o ? { expires_at: o } : {}
      }
    }), "Bootstrap token created. Copy the secret now; it is shown once.");
    l && typeof l == "object" && "secret" in l && typeof l.secret == "string" && (p({
      label: "Bootstrap token secret",
      value: String(l.secret)
    }), r.reset());
  }
  async function re(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("scopes") ?? "").split(",").map((e) => e.trim()).filter(Boolean), o = a.length ? a : ["tenant:read"], s = await te("create-service-account", () => L(t, n, "/v1/service-accounts", {
      method: "POST",
      body: {
        name: String(i.get("name") ?? "").trim() || "Automation account",
        role: String(i.get("role") ?? "viewer"),
        scopes: o,
        ...ba(String(i.get("expiry") ?? "")) ? { expires_at: ba(String(i.get("expiry") ?? "")) } : {}
      }
    }), "Service account created. Copy the API secret now; it is shown once.");
    s && typeof s == "object" && "secret" in s && typeof s.secret == "string" && (p({
      label: "Service API secret",
      value: String(s.secret)
    }), r.reset());
  }
  async function ie(e) {
    e && await te(`revoke-bootstrap-${e}`, () => L(t, n, `/v1/bootstrap-tokens/${e}/revoke`, { method: "POST" }), "Bootstrap token revoked.");
  }
  async function ae(e) {
    e && await te(`revoke-service-${e}`, () => L(t, n, `/v1/service-accounts/${e}/revoke`, { method: "POST" }), "Service account revoked.");
  }
  async function oe(e) {
    if (!e) return;
    let r = await te(`rotate-service-${e}`, () => L(t, n, `/v1/service-accounts/${e}/rotate`, { method: "POST" }), "Service account rotated. Copy the new API secret now; it is shown once.");
    r && typeof r == "object" && "secret" in r && typeof r.secret == "string" && p({
      label: "Rotated service API secret",
      value: String(r.secret)
    });
  }
  async function k(e) {
    e.preventDefault();
    let r = new FormData(e.currentTarget), i = String(r.get("name") ?? "").trim();
    if (!i) {
      d("Organization name is required.");
      return;
    }
    await te("save-organization", () => L(t, n, "/v1/tenants/current", {
      method: "PATCH",
      body: { name: i }
    }), "Organization settings saved.");
  }
  async function A(e) {
    e.preventDefault();
    let r = new FormData(e.currentTarget), i = Number(r.get("metadata_retention_days") ?? 90), a = Number(r.get("report_days") ?? 365), o = Number(r.get("audit_log_days") ?? 2555), s = Number(r.get("high_scale_artifact_days") ?? 2555), c = r.get("legal_hold") === "on";
    await te("save-retention", () => L(t, n, "/v1/tenants/current", {
      method: "PATCH",
      body: { privacy_settings: {
        metadata_retention_days: i,
        evidence_retention: {
          report_days: a,
          audit_log_days: o,
          high_scale_artifact_days: s,
          legal_hold: c
        }
      } }
    }), "Retention policy saved. Metadata purge runs immediately when retention days change.");
  }
  async function se(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("purpose") ?? "").trim(), o = String(i.get("name") ?? "").trim(), s = String(i.get("plaintext") ?? "").trim();
    if (!a || !o || !s) {
      d("Purpose, name, and credential value are required.");
      return;
    }
    await te("create-vault-secret", () => L(t, n, "/v1/secrets", {
      method: "POST",
      body: {
        purpose: a,
        name: o,
        plaintext: s,
        metadata: { source: "settings_vault" }
      }
    }), "Integration secret stored. Plaintext is never returned by list APIs."), r.reset();
  }
  async function ce(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("secret_id") ?? m).trim(), o = String(i.get("plaintext") ?? "").trim();
    if (!a || !o) {
      d("Select a secret and provide the replacement credential value.");
      return;
    }
    await te(`rotate-vault-${a}`, () => L(t, n, `/v1/secrets/${a}/rotate`, {
      method: "POST",
      body: { plaintext: o }
    }), "Secret rotated. Prior credential stops working for authorized internal workflows."), r.reset(), h("");
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: "settings" }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: i,
        options: D,
        onChange: a,
        className: "tabs-wrap"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Organization",
            value: Y(g ?? {}, ["name"], "Not loaded"),
            sub: Y(g ?? {}, ["id"], e.state?.tenant_id ?? "—"),
            icon: N,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Secret vault",
            value: e.secrets.length,
            sub: "Encrypted integration credentials",
            icon: M,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Metadata retention",
            value: `${y}d`,
            sub: "Tenant privacy_settings from API",
            icon: j,
            tone: "muted"
          })
        ]
      }),
      (c || u) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: u ? "form-banner error" : "form-banner",
        children: u || c
      }),
      f && /* @__PURE__ */ (0, R.jsxs)(H, {
        className: "secret-card",
        children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: f.label }), /* @__PURE__ */ (0, R.jsx)(G, { children: "This value is shown once. It is not returned by list APIs and will not be visible after refresh." })] }), /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(B, {
            variant: "secondary",
            size: "sm",
            onClick: () => {
              navigator.clipboard.writeText(f.value).then(() => {
                l("Secret copied to clipboard."), d("");
              }).catch(() => {
                d("Clipboard copy failed. Select the secret manually.");
              });
            },
            children: "Copy secret"
          }), /* @__PURE__ */ (0, R.jsx)(B, {
            variant: "ghost",
            size: "sm",
            onClick: () => p(null),
            children: "Dismiss"
          })]
        })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)("pre", {
          className: "codeblock",
          children: f.value
        }) })]
      }),
      i === "organization" && /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Organization profile" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Tenant name from `GET/PATCH /v1/tenants/current`. Privacy defaults stay metadata-only." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: g ? /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: k,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Organization name" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "name",
                defaultValue: Y(g, ["name"]),
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Tenant ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
              value: Y(g, ["id"]),
              readOnly: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Data region" }), /* @__PURE__ */ (0, R.jsx)("input", {
              value: Y(g, ["data_region"], "unrecorded"),
              readOnly: !0
            })] }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: o !== "",
                children: o === "save-organization" ? "Saving..." : "Save organization"
              })
            })
          ]
        }) : /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: "Tenant record unavailable.",
          body: "`GET /v1/tenants/current` did not return data for this session."
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Workspace inventory" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Live counts from tenant APIs; not editable here." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target groups" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: e.targetGroups.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Agents" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: e.agents.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Evidence records" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: e.evidence.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environments" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: new Set(e.targetGroups.map((e) => Y(e, ["environment_id"], "unassigned"))).size })] })
          ]
        })] })]
      }),
      i === "users" && /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Current session" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Read-only view of the authenticated principal in this browser session." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "User ID" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: n.user_id ?? "—" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Role" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: n.role ?? "—" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Tenant" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: n.tenant_id ?? e.state?.tenant_id ?? "—" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Auth mode" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: t.authMode })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [
          /* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "User provisioning boundary" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Read-only — no customer tenant user API is wired in this release." })] }),
          /* @__PURE__ */ (0, R.jsxs)(K, {
            className: "settings-list",
            children: [
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(Ne, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Invite, disable, and role assignment are provisioned by AstraNull staff through `/internal/admin/*` routes." })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Enterprise SSO group-to-role mapping is enforced at the IdP/JWT layer when `auth_mode` is `oidc-jwt`." })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(j, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Customer admins can review audit entries and API credentials here; user directory management remains staff-operated." })] })
            ]
          }),
          /* @__PURE__ */ (0, R.jsxs)(K, {
            className: "row-actions",
            children: [/* @__PURE__ */ (0, R.jsx)(V, {
              href: "#admin",
              variant: "secondary",
              size: "sm",
              children: "Staff admin console"
            }), w ? /* @__PURE__ */ (0, R.jsx)(V, {
              href: "#audit",
              variant: "ghost",
              size: "sm",
              children: "Tenant audit log"
            }) : null]
          })
        ] })]
      }),
      i === "api-keys" && /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create bootstrap token" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Issue a short-lived one-time install secret for outbound agent registration." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
            className: "product-form",
            onSubmit: ne,
            children: [
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "name",
                placeholder: "prod-edge-install"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environment" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "environment_id",
                defaultValue: "env_demo"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "target_group_id",
                defaultValue: "",
                children: [/* @__PURE__ */ (0, R.jsx)("option", {
                  value: "",
                  children: "No default binding"
                }), e.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                  value: Y(e, ["id"]),
                  children: Y(e, ["name", "id"])
                }, Y(e, ["id"])))]
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Expiry" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "expiry",
                defaultValue: "1h",
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "15m",
                    children: "15 minutes"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "1h",
                    children: "1 hour"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "24h",
                    children: "24 hours"
                  })
                ]
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Max registrations" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "max_registrations",
                type: "number",
                min: "1",
                max: "50",
                defaultValue: "1"
              })] }),
              /* @__PURE__ */ (0, R.jsx)("div", {
                className: "form-actions full",
                children: /* @__PURE__ */ (0, R.jsx)(B, {
                  type: "submit",
                  disabled: o !== "",
                  children: o === "create-bootstrap-token" ? "Creating..." : "Create token"
                })
              })
            ]
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create service account" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Create scoped API automation credentials. Secrets are returned once and list views stay redacted." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
            className: "product-form",
            onSubmit: re,
            children: [
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "name",
                placeholder: "ci-evidence-reader"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Role" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "role",
                defaultValue: "viewer",
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "viewer",
                    children: "Viewer"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "auditor",
                    children: "Auditor"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "engineer",
                    children: "Engineer"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "admin",
                    children: "Admin"
                  })
                ]
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", {
                className: "full",
                children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Scopes" }), /* @__PURE__ */ (0, R.jsx)("input", {
                  name: "scopes",
                  defaultValue: "tenant:read,evidence:read"
                })]
              }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Expiry" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "expiry",
                defaultValue: "",
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "",
                    children: "No expiry"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "24h",
                    children: "24 hours"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "30d",
                    children: "30 days"
                  })
                ]
              })] }),
              /* @__PURE__ */ (0, R.jsx)("div", {
                className: "form-actions full",
                children: /* @__PURE__ */ (0, R.jsx)(B, {
                  type: "submit",
                  disabled: o !== "",
                  children: o === "create-service-account" ? "Creating..." : "Create API key"
                })
              })
            ]
          }) })] })]
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Bootstrap tokens" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Install tokens are redacted after creation and can be revoked immediately." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
          tone: "info",
          children: [e.bootstrapTokens.length, " records"]
        })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: O,
          items: e.bootstrapTokens,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: M,
            title: "No bootstrap tokens.",
            body: "Create a short-lived token before installing an outbound-only agent."
          })
        }) })] }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Service accounts" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Automation credentials are scoped, auditable, rotatable, and redacted after creation." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
          tone: "success",
          children: [e.serviceAccounts.length, " records"]
        })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: ee,
          items: e.serviceAccounts,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: je,
            title: "No service accounts.",
            body: "Create an API key only for a clear automation owner and scope."
          })
        }) })] })
      ] }),
      i === "sso" && /* @__PURE__ */ (0, R.jsxs)(H, { children: [
        /* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Enterprise SSO posture" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Read-only auth configuration from `/ready` and `/v1/public/site-config`. Secrets and JWKS URLs are never exposed." })] }),
        /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Auth mode" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: b.authMode })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "OIDC issuer" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: b.issuer ?? "Not exposed on public readiness endpoints" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "OIDC audience" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: b.audience ?? "Not exposed on public readiness endpoints" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Bundled staging login" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: b.bundledStagingLogin ? "Enabled" : "Disabled" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Login URL" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: t.loginUrl })] })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "settings-list",
          children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Production human auth defaults to `oidc-jwt` with JWKS verification; developer validation may use `dev-headers` or bundled staging login." })] }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(M, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Issuer and audience values are configured server-side. Public site-config currently exposes `auth_mode` only unless your deployment extends the payload." })] })]
        })
      ] }),
      i === "retention" && /* @__PURE__ */ (0, R.jsxs)(H, { children: [
        /* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Privacy and retention" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "`PATCH /v1/tenants/current` updates `privacy_settings.metadata_retention_days` and `evidence_retention`. Metadata purge runs immediately when retention changes." })] }),
        /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: A,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Metadata retention (days)" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "metadata_retention_days",
              type: "number",
              min: "1",
              max: "3650",
              defaultValue: y
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Report archive (days)" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "report_days",
              type: "number",
              min: "30",
              max: "3650",
              defaultValue: $i(v, ["report_days"], 365)
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Audit log retention (days)" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "audit_log_days",
              type: "number",
              min: "365",
              max: "3650",
              defaultValue: $i(v, ["audit_log_days"], 2555)
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "High-scale artifact retention (days)" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "high_scale_artifact_days",
              type: "number",
              min: "365",
              max: "3650",
              defaultValue: $i(v, ["high_scale_artifact_days"], 2555)
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "check-row full",
              children: [/* @__PURE__ */ (0, R.jsx)("input", {
                name: "legal_hold",
                type: "checkbox",
                defaultChecked: !!v.legal_hold
              }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Legal hold — block metadata deletions while legal hold is active (read-only boundary for production legal workflows)." })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: o !== "" || !g,
                children: o === "save-retention" ? "Saving..." : "Save retention policy"
              })
            })
          ]
        }) }),
        /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "settings-list",
          children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(j, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Metadata retention applies to events, evidence vault, reports, and notification events for the current tenant." })] }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Audit logs, findings, test runs, and authorization artifacts follow separate production gates documented in `docs/api.md`." })] })]
        })
      ] }),
      i === "secrets" && /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Store integration secret" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Plaintext is accepted only on create/rotate. List APIs return metadata-only envelopes." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: se,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Purpose" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "purpose",
              defaultValue: "integration_credential",
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "integration_credential",
                  children: "Integration credential"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "waf_connector",
                  children: "WAF connector"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "webhook_signing",
                  children: "Webhook signing"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "provider_api",
                  children: "Provider API"
                })
              ]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "name",
              placeholder: "cloudflare:edge-readonly",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Credential value" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "plaintext",
                rows: 4,
                placeholder: "API token or JSON credential",
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: o !== "",
                children: o === "create-vault-secret" ? "Storing..." : "Store secret"
              })
            })
          ]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Rotate stored secret" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Rotation replaces the encrypted envelope; there is no decrypt endpoint on `/v1`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: ce,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Secret" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "secret_id",
                value: m,
                onChange: (e) => h(e.target.value),
                required: !0,
                children: [/* @__PURE__ */ (0, R.jsx)("option", {
                  value: "",
                  children: "Select secret"
                }), e.secrets.map((e) => /* @__PURE__ */ (0, R.jsxs)("option", {
                  value: Y(e, ["id"]),
                  children: [
                    Y(e, ["name"]),
                    " · ",
                    Y(e, ["purpose"])
                  ]
                }, Y(e, ["id"])))]
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Replacement credential" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "plaintext",
                rows: 4,
                placeholder: "New API token or JSON credential",
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: o !== "" || e.secrets.length === 0,
                children: "Rotate secret"
              })
            })
          ]
        }) })] })]
      }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Secret vault inventory" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Tenant-scoped metadata from `GET /v1/secrets` — no plaintext, ciphertext, or auth tags." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
        tone: "info",
        children: [e.secrets.length, " records"]
      })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "name",
            label: "Name",
            render: (e) => Y(e, ["name", "id"])
          },
          {
            key: "purpose",
            label: "Purpose",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: "info",
              children: Y(e, ["purpose"])
            })
          },
          {
            key: "rotation",
            label: "Rotation",
            render: (e) => $i(e, ["rotation"])
          },
          {
            key: "updated",
            label: "Updated",
            render: (e) => I(e.updated_at ?? e.created_at)
          },
          {
            key: "actions",
            label: "Actions",
            render: (e) => {
              let t = Y(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "secondary",
                disabled: o !== "",
                onClick: () => {
                  h(t), a("secrets");
                },
                children: "Rotate"
              });
            }
          }
        ],
        items: e.secrets,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: M,
          title: "No secrets stored.",
          body: "Store connector or integration credentials here before referencing them from read-only connector workflows.",
          actionLabel: "Open Integrations",
          actionHref: "#integrations"
        })
      }) })] })] }),
      i === "audit" && /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Recent tenant audit entries" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Preview from `GET /v1/audit-log`. Full immutable history is on the Audit page." })] }), /* @__PURE__ */ (0, R.jsx)(V, {
        href: "#audit",
        variant: "secondary",
        size: "sm",
        children: "Open audit log"
      })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "action",
            label: "Action",
            render: (e) => Y(e, ["action"])
          },
          {
            key: "resource",
            label: "Resource",
            render: (e) => `${Y(e, ["resource_type"], "record")} · ${Y(e, ["resource_id"])}`
          },
          {
            key: "actor",
            label: "Actor",
            render: (e) => Y(e, ["actor_role", "actor_user_id"])
          },
          {
            key: "created",
            label: "Recorded",
            render: (e) => I(e.created_at)
          }
        ],
        items: e.audit.slice(0, 20),
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: j,
          title: "No audit entries yet.",
          body: "Security-sensitive actions will appear here after tokens, agents, retention, or validation changes are recorded."
        })
      }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Related governance links" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Settings surfaces credentials and retention; audit and release evidence stay in dedicated routes." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "row-actions",
        children: [
          T ? /* @__PURE__ */ (0, R.jsx)(V, {
            href: "#notifications",
            variant: "secondary",
            size: "sm",
            children: "Notification rules"
          }) : null,
          E ? /* @__PURE__ */ (0, R.jsx)(V, {
            href: "#release-evidence",
            variant: "secondary",
            size: "sm",
            children: "Release evidence"
          }) : null,
          /* @__PURE__ */ (0, R.jsx)(V, {
            href: "#integrations",
            variant: "ghost",
            size: "sm",
            children: "Integrations"
          })
        ]
      })] })] })
    ]
  });
}
function wa({ data: e }) {
  let t = Qi({
    targetGroups: e.targetGroups,
    runs: e.runs,
    findings: e.findings
  });
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, { route: "environments" }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Environment readiness" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Segment declared groups by operational environment and current validation evidence." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
      className: "environment-grid",
      children: t.length ? t.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "environment-card",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.id }), /* @__PURE__ */ (0, R.jsx)(z, {
            tone: e.coverage === 100 && e.openFindings === 0 ? "success" : e.coverage > 0 ? "warn" : "danger",
            children: e.state
          })] }),
          /* @__PURE__ */ (0, R.jsx)(Or, { value: e.coverage }),
          /* @__PURE__ */ (0, R.jsxs)("span", { children: [e.groups.length, " declared target groups"] }),
          /* @__PURE__ */ (0, R.jsxs)("span", { children: [e.completedRuns, " completed or verdicted runs"] }),
          /* @__PURE__ */ (0, R.jsxs)("span", { children: [e.openFindings, " open findings"] })
        ]
      }, e.id)) : /* @__PURE__ */ (0, R.jsx)(q, {
        icon: Te,
        title: "No environments yet.",
        body: "Create a declared target group with an environment ID to populate this view.",
        actionLabel: "Open Target Groups",
        actionHref: "#target-groups"
      })
    })] })]
  });
}
function Ta({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), u = e.checks.filter((e) => Y(e, ["safety_class"]) === "safe"), d = e.checks.filter((e) => Y(e, ["safety_class"]) === "soc_gated"), f = [
    {
      key: "target",
      label: "Target group",
      render: (e) => Y(e.target_group && typeof e.target_group == "object" ? e.target_group : {}, ["name", "id"], Y(e, ["target_group_id"]))
    },
    {
      key: "check",
      label: "Check",
      render: (e) => Y(e.check && typeof e.check == "object" ? e.check : {}, ["name", "check_id"], Y(e, ["check_id"]))
    },
    {
      key: "state",
      label: "State",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: Y(e, ["state"], "active") === "paused" ? "warn" : "success",
        children: Y(e, ["state"], "active")
      })
    },
    {
      key: "cadence",
      label: "Cadence",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Y(e, ["cadence"])
      })
    },
    {
      key: "expected",
      label: "Expected verdict",
      render: (e) => Y(e, ["expected_verdict"])
    },
    {
      key: "targets",
      label: "Targets",
      render: (e) => $i(e, ["target_count"])
    },
    {
      key: "updated",
      label: "Updated",
      render: (e) => I(e.updated_at ?? e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], ""), n = Y(e, ["state"], "active");
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void h(t, { cadence: "weekly" }, "Policy cadence updated to weekly."),
              children: "Weekly"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void h(t, { state: n === "paused" ? "active" : "paused" }, n === "paused" ? "Policy resumed." : "Policy paused."),
              children: n === "paused" ? "Resume" : "Pause"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "danger",
              disabled: i !== "",
              onClick: () => void g(t),
              children: "Archive"
            })
          ]
        });
      }
    }
  ];
  async function p(e, t, n) {
    a(e), l(""), s("");
    try {
      let e = await t();
      return s(n), await r(), e;
    } catch (e) {
      let t = e.payload;
      return l(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Action failed.")), null;
    } finally {
      a("");
    }
  }
  async function m(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("target_group_id") ?? "").trim(), o = String(i.get("check_id") ?? "").trim();
    if (!a || !o) {
      l("Select a target group and safe check before creating a policy.");
      return;
    }
    let s = String(i.get("safe_window_day") ?? "").trim(), c = String(i.get("safe_window_start") ?? "").trim(), u = String(i.get("safe_window_end") ?? "").trim(), d = s && c && u ? [{
      day: s,
      start: c,
      end: u,
      timezone: String(i.get("safe_window_timezone") ?? "UTC").trim() || "UTC"
    }] : [];
    await p("create-test-policy", () => L(t, n, "/v1/test-policies", {
      method: "POST",
      body: {
        target_group_id: a,
        check_id: o,
        cadence: String(i.get("cadence") ?? "manual"),
        expected_verdict: String(i.get("expected_verdict") ?? "pass"),
        safe_windows: d
      }
    }), "Test policy created from declared scope and safe check catalog.") && r.reset();
  }
  async function h(e, r, i) {
    e && await p(`patch-policy-${e}`, () => L(t, n, `/v1/test-policies/${e}`, {
      method: "PATCH",
      body: r
    }), i);
  }
  async function g(e) {
    e && await p(`archive-policy-${e}`, () => L(t, n, `/v1/test-policies/${e}`, { method: "DELETE" }), "Test policy archived.");
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "test-policies",
        eyebrow: "Policy binding"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Active policies",
            value: e.testPolicies.length,
            sub: "Tenant API policy records",
            icon: se,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Safe checks",
            value: u.length,
            sub: "Customer-runnable catalog",
            icon: pe,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "SOC-gated checks",
            value: d.length,
            sub: "Request-only, not policy-created",
            icon: N,
            tone: "warn"
          })
        ]
      }),
      (o || c) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c ? "form-banner error" : "form-banner",
        children: c || o
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create safe validation policy" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Bind a customer-runnable safe check to an active declared target group. SOC-gated checks remain request-only." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
        className: "product-form",
        onSubmit: m,
        children: [
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsxs)("select", {
            name: "target_group_id",
            required: !0,
            defaultValue: "",
            children: [/* @__PURE__ */ (0, R.jsx)("option", {
              value: "",
              children: "Select declared group"
            }), e.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
              value: Y(e, ["id"]),
              children: Y(e, ["name", "id"])
            }, Y(e, ["id"])))]
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Safe check" }), /* @__PURE__ */ (0, R.jsxs)("select", {
            name: "check_id",
            required: !0,
            defaultValue: "",
            children: [/* @__PURE__ */ (0, R.jsx)("option", {
              value: "",
              children: "Select safe check"
            }), u.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
              value: Y(e, ["check_id"]),
              children: Y(e, ["name", "check_id"])
            }, Y(e, ["check_id"])))]
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Cadence" }), /* @__PURE__ */ (0, R.jsxs)("select", {
            name: "cadence",
            defaultValue: "weekly",
            children: [
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "manual",
                children: "Manual"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "daily",
                children: "Daily"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "weekly",
                children: "Weekly"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "monthly",
                children: "Monthly"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "event_driven",
                children: "Event-driven"
              })
            ]
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Expected verdict" }), /* @__PURE__ */ (0, R.jsxs)("select", {
            name: "expected_verdict",
            defaultValue: "pass",
            children: [
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "pass",
                children: "Pass"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "warn",
                children: "Warn"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "fail",
                children: "Fail"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "manual_review",
                children: "Manual review"
              })
            ]
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Safe window day" }), /* @__PURE__ */ (0, R.jsx)("input", {
            name: "safe_window_day",
            placeholder: "Mon"
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Window timezone" }), /* @__PURE__ */ (0, R.jsx)("input", {
            name: "safe_window_timezone",
            defaultValue: "UTC"
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Window start" }), /* @__PURE__ */ (0, R.jsx)("input", {
            name: "safe_window_start",
            type: "time"
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Window end" }), /* @__PURE__ */ (0, R.jsx)("input", {
            name: "safe_window_end",
            type: "time"
          })] }),
          /* @__PURE__ */ (0, R.jsx)("div", {
            className: "form-actions full",
            children: /* @__PURE__ */ (0, R.jsx)(B, {
              type: "submit",
              disabled: i !== "" || e.targetGroups.length === 0 || u.length === 0,
              children: i === "create-test-policy" ? "Creating..." : "Create policy"
            })
          })
        ]
      }) })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Safe validation policies" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "All rows are `/v1/test-policies` records enriched with active target-group and check catalog metadata." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
        tone: "info",
        children: [e.testPolicies.length, " active"]
      })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: f,
        items: e.testPolicies,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: se,
          title: "No test policies yet.",
          body: "Create a safe validation policy after declaring target groups and reviewing the safe check catalog."
        })
      }) })] })
    ]
  });
}
var Ea = [
  {
    value: "waf_policy",
    label: "WAF policy"
  },
  {
    value: "cdn_property",
    label: "CDN property"
  },
  {
    value: "dns_zone",
    label: "DNS zone"
  },
  {
    value: "cloud_asset",
    label: "Cloud asset"
  },
  {
    value: "vulnerability",
    label: "Vulnerability"
  }
];
function Da({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)([]), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(""), m = e.deploymentFeatures, h = m?.connectors === !0, g = e.connectors.filter((e) => Y(e, ["status"], "").toLowerCase() !== "disabled"), _ = Y(g.find((e) => Y(e, ["id"], "") === i) ?? g[0] ?? {}, ["id"], ""), v = [
    {
      key: "name",
      label: "Connector",
      render: (e) => Y(e, ["name", "id"])
    },
    {
      key: "provider",
      label: "Provider",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Y(e, ["provider"])
      })
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: Y(e, ["status"]) === "active" ? "success" : Y(e, ["status"]) === "error" ? "danger" : "muted",
        children: Y(e, ["status"])
      })
    },
    {
      key: "secret",
      label: "Secret ref",
      render: (e) => Y(e, ["secret_id"], "manual snapshots only")
    },
    {
      key: "updated",
      label: "Updated",
      render: (e) => I(e.updated_at ?? e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Y(e, ["id"], ""), n = Y(e, ["status"], "").toLowerCase() === "disabled";
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: c !== "" || n,
              onClick: () => void x(t),
              children: "Validate"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: c !== "" || n,
              onClick: () => void S(t),
              children: "Poll"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "ghost",
              disabled: c !== "",
              onClick: () => void T(t),
              children: "Snapshots"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "danger",
              disabled: c !== "" || n,
              onClick: () => void w(t),
              children: "Disable"
            })
          ]
        });
      }
    }
  ];
  async function y(e, t, n) {
    l(e), p(""), d("");
    try {
      let e = await t();
      return d(n), await r(), e;
    } catch (e) {
      let t = e.payload;
      return p(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Action failed.")), null;
    } finally {
      l("");
    }
  }
  async function b(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), o = String(i.get("provider") ?? "cloudflare"), s = String(i.get("name") ?? "").trim(), c = String(i.get("secret") ?? "").trim(), l = String(i.get("secret_id") ?? "").trim(), u = String(i.get("resource_ref_hash") ?? "").trim(), d = String(i.get("region") ?? "").trim(), f = String(i.get("default_snapshot_kind") ?? "waf_policy");
    if (!s) {
      p("Connector name is required.");
      return;
    }
    await y("create-connector", async () => {
      let e = l || null;
      c && (e = (await L(t, n, "/v1/secrets", {
        method: "POST",
        body: {
          purpose: "waf_connector",
          name: `${o}:${s}`,
          plaintext: c,
          metadata: {
            provider: o,
            read_only: !0
          }
        }
      })).secret?.id ?? null);
      let i = await L(t, n, "/v1/connectors", {
        method: "POST",
        body: {
          provider: o,
          name: s,
          ...e ? { secret_id: e } : {},
          status: "active",
          config: {
            read_only: !0,
            default_snapshot_kind: f,
            ...o === "cloudflare" && u ? { zone_ref_hash: u } : {},
            ...o === "aws_waf" && u ? { resource_ref_hash: u } : {},
            ...o === "aws_waf" && d ? { region_summary: d } : {}
          }
        }
      });
      return r.reset(), i.connector?.id && a(String(i.connector.id)), i;
    }, "Connector created from backend API.");
  }
  async function x(e) {
    e && await y(`validate-${e}`, () => L(t, n, `/v1/connectors/${e}/validate`, { method: "POST" }), "Connector validation completed.");
  }
  async function S(e) {
    if (!e) return;
    let r = await y(`poll-${e}`, () => L(t, n, `/v1/connectors/${e}/poll`, {
      method: "POST",
      body: {}
    }), "Connector poll requested."), i = r && typeof r == "object" && "snapshots" in r ? r.snapshots : null;
    Array.isArray(i) && s(i);
  }
  async function w(e) {
    e && await y(`disable-${e}`, () => L(t, n, `/v1/connectors/${e}/disable`, {
      method: "POST",
      body: { reason: "Disabled from integrations page." }
    }), "Connector disabled.");
  }
  async function T(e) {
    if (!e) return;
    let r = await y(`snapshots-${e}`, () => L(t, n, `/v1/connectors/${e}/snapshots`), "Connector snapshots loaded."), i = r && typeof r == "object" && "items" in r ? r.items : null;
    s(Array.isArray(i) ? i : []), a(e);
  }
  async function E(e) {
    e.preventDefault();
    let r = e.currentTarget, i = _;
    if (!i) {
      p("Create or select a connector before adding a snapshot.");
      return;
    }
    let a = new FormData(r), o = String(a.get("hostnames") ?? "").split(",").map((e) => e.trim()).filter(Boolean), c = Number(a.get("rule_count") ?? 0), l = {
      snapshot_kind: String(a.get("snapshot_kind") ?? "waf_policy"),
      display_ref: String(a.get("display_ref") ?? "").trim(),
      resource_ref_hash: String(a.get("resource_ref_hash") ?? "").trim(),
      config_hash: String(a.get("config_hash") ?? "").trim(),
      summary: {
        policy_mode: String(a.get("policy_mode") ?? "monitor"),
        rule_count: Number.isFinite(c) ? c : 0,
        ...o.length ? { hostnames: o } : {}
      }
    };
    if (!l.display_ref || !l.resource_ref_hash || !l.config_hash) {
      p("Display ref, resource hash, and config hash are required for a metadata snapshot.");
      return;
    }
    let u = await y(`snapshot-${i}`, () => L(t, n, `/v1/connectors/${i}/poll`, {
      method: "POST",
      body: {
        manual_only: !0,
        snapshots: [l]
      }
    }), "Manual connector snapshot ingested."), d = u && typeof u == "object" && "snapshots" in u ? u.snapshots : null;
    Array.isArray(d) && s(d), r.reset();
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "integrations",
        eyebrow: "Connectors"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Connectors",
            value: e.connectors.length,
            sub: h ? "Tenant feature enabled" : "Feature flag disabled",
            icon: be,
            tone: h ? "success" : "muted"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Secret refs",
            value: e.secrets.length,
            sub: "Redacted vault entries visible to this role",
            icon: M,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "WAF posture",
            value: m?.waf_posture ? "on" : "off",
            sub: "Optional posture enrichment",
            icon: N,
            tone: m?.waf_posture ? "success" : "muted"
          })
        ]
      }),
      h ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create read-only connector" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Store a provider credential in the secret vault or reference an existing secret, then create a metadata-only connector." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
            className: "product-form",
            onSubmit: b,
            children: [
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Provider" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "provider",
                defaultValue: "cloudflare",
                children: [/* @__PURE__ */ (0, R.jsx)("option", {
                  value: "cloudflare",
                  children: "Cloudflare"
                }), /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "aws_waf",
                  children: "AWS WAF"
                })]
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "name",
                placeholder: "edge-readonly",
                required: !0
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", {
                className: "full",
                children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "API key or credential JSON" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                  name: "secret",
                  rows: 4,
                  placeholder: "Cloudflare token, or AWS JSON: {\"access_key_id\":\"...\",\"secret_access_key\":\"...\",\"region\":\"us-east-1\"}"
                })]
              }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Existing secret ref" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "secret_id",
                placeholder: "secret_..."
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Resource hash" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "resource_ref_hash",
                placeholder: "Optional zone/web ACL hash"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "AWS region" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "region",
                placeholder: "us-east-1"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Snapshot kind" }), /* @__PURE__ */ (0, R.jsx)("select", {
                name: "default_snapshot_kind",
                defaultValue: "waf_policy",
                children: Ea.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                  value: e.value,
                  children: e.label
                }, e.value))
              })] }),
              /* @__PURE__ */ (0, R.jsx)("div", {
                className: "form-actions full",
                children: /* @__PURE__ */ (0, R.jsx)(B, {
                  disabled: c !== "",
                  type: "submit",
                  children: c === "create-connector" ? "Creating..." : "Create connector"
                })
              })
            ]
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Manual metadata snapshot" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Use this when provider polling is unavailable or encryption is not configured locally." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
            className: "product-form",
            onSubmit: E,
            children: [
              /* @__PURE__ */ (0, R.jsxs)("label", {
                className: "full",
                children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Connector" }), /* @__PURE__ */ (0, R.jsx)("select", {
                  value: _,
                  onChange: (e) => a(e.target.value),
                  children: g.map((e) => /* @__PURE__ */ (0, R.jsxs)("option", {
                    value: Y(e, ["id"]),
                    children: [
                      Y(e, ["name"]),
                      " - ",
                      Y(e, ["provider"])
                    ]
                  }, Y(e, ["id"])))
                })]
              }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Snapshot kind" }), /* @__PURE__ */ (0, R.jsx)("select", {
                name: "snapshot_kind",
                defaultValue: "waf_policy",
                children: Ea.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                  value: e.value,
                  children: e.label
                }, e.value))
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Display ref" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "display_ref",
                placeholder: "zone-a",
                required: !0
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Resource hash" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "resource_ref_hash",
                placeholder: "res_hash_1",
                required: !0
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Config hash" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "config_hash",
                placeholder: "cfg_hash_1",
                required: !0
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Policy mode" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                name: "policy_mode",
                defaultValue: "monitor",
                children: [
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "block",
                    children: "Block"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "monitor",
                    children: "Monitor"
                  }),
                  /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "unknown",
                    children: "Unknown"
                  })
                ]
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Rule count" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "rule_count",
                type: "number",
                min: "0",
                defaultValue: "0"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", {
                className: "full",
                children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Hostnames" }), /* @__PURE__ */ (0, R.jsx)("input", {
                  name: "hostnames",
                  placeholder: "app.example.com, api.example.com"
                })]
              }),
              /* @__PURE__ */ (0, R.jsx)("div", {
                className: "form-actions full",
                children: /* @__PURE__ */ (0, R.jsx)(B, {
                  disabled: c !== "" || !_,
                  type: "submit",
                  children: "Ingest snapshot"
                })
              })
            ]
          }) })] })]
        }),
        (u || f) && /* @__PURE__ */ (0, R.jsx)("div", {
          className: f ? "form-banner error" : "form-banner",
          children: f || u
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Configured connectors" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Actions call `/v1/connectors` and never render plaintext credentials." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
          tone: "info",
          children: [e.connectors.length, " total"]
        })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: v,
          items: e.connectors,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: be,
            title: "No connectors configured.",
            body: "Create a read-only connector or continue using manual evidence workflows without provider access."
          })
        }) })] }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Connector snapshots" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Snapshots come from backend poll results or manual metadata ingest." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
          tone: "muted",
          children: [o.length, " loaded"]
        })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "queue-list",
          children: o.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No snapshots loaded.",
            body: "Select a connector action to load or ingest metadata snapshots."
          }) : o.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(z, {
            tone: "info",
            children: Y(e, ["snapshot_kind"])
          }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
            Y(e, ["display_ref"]),
            " - ",
            I(e.observed_at ?? e.created_at)
          ] })] }, Y(e, ["id"])))
        })] })
      ] }) : /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Connectors are disabled for this tenant" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Enable `ASTRANULL_WAF_POSTURE_ENABLED=1` and `ASTRANULL_CONNECTORS_ENABLED=1`, or grant a tenant override, to manage read-only connectors." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "callout-list",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", {
          className: "callout info",
          children: [/* @__PURE__ */ (0, R.jsx)(N, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Core DDoS validation still works from declared target groups without cloud credentials." })]
        }), /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "callout",
          children: [/* @__PURE__ */ (0, R.jsx)(j, { size: 18 }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Connector credentials must be stored as encrypted secret references before provider polling." })]
        })]
      })] })
    ]
  });
}
function Oa({ data: e, session: t }) {
  let n = e.subscriptionSummary, r = ta(n, ["support"]), i = ta(n, ["usage"]), a = ta(n, ["account"]), o = na(r, ["recent_audit"]), s = $i(i ?? {}, ["open_findings"]), c = $i(i ?? {}, ["pending_high_scale_requests"]), l = Y(r ?? {}, ["owner"], "Unassigned"), u = Y(r ?? {}, ["escalation_state"], n ? "nominal" : "No record"), d = !!(e.state?.kill_switch?.active ?? e.state?.kill_switch?.enabled), f = {
    principal: t.principal,
    staffRole: t.staff_role
  }, p = t.role ?? "admin", m = tr(p, "notifications", f), h = tr(p, "release-evidence", f), g = e.releaseEvidence.find((e) => Y(e, ["kind"]) === "support_readiness") ?? null, _ = n ? [
    {
      label: "Support owner",
      value: l,
      icon: fe
    },
    {
      label: "Account lifecycle",
      value: Y(a ?? r ?? {}, ["lifecycle_state"], "unrecorded"),
      icon: N
    },
    {
      label: "Region",
      value: Y(a ?? r ?? {}, ["region"], "unrecorded"),
      icon: ge
    },
    {
      label: "Recent tenant audit records",
      value: pn($i(i ?? {}, ["audit_events"])),
      icon: j
    }
  ] : [];
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "support",
        eyebrow: "Readiness support"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Support owner",
            value: l,
            sub: "From tenant account metadata",
            icon: fe,
            tone: l === "Unassigned" ? "muted" : "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Open findings",
            value: s,
            sub: "Tenant-scoped finding records",
            icon: Ae,
            tone: s > 0 ? "warn" : "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "SOC escalations",
            value: c,
            sub: u.replaceAll("_", " "),
            icon: De,
            tone: c > 0 ? "warn" : "success"
          })
        ]
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Support readiness" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Tenant support posture from account, findings, high-scale, and audit records." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "settings-list",
          children: _.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: fe,
            title: "No support account record.",
            body: "Approve a signup request or attach tenant account metadata before support readiness can show live ownership."
          }) : _.map(({ label: e, value: t, icon: n }) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(n, { size: 18 }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
            e,
            ": ",
            /* @__PURE__ */ (0, R.jsx)("strong", { children: t })
          ] })] }, e))
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Recent support evidence" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Latest tenant audit events exposed as metadata-only support context." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "queue-list",
          children: o.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No recent support evidence.",
            body: "Tenant audit entries will appear here after support-relevant actions are recorded."
          }) : o.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(z, {
            tone: "info",
            children: Y(e, ["resource_type"], "audit")
          }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
            Y(e, ["action"]),
            " - ",
            I(e.created_at)
          ] })] }, Y(e, [
            "id",
            "created_at",
            "action"
          ])))
        })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [
        /* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Support workflows" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Customer-safe escalation paths that stay within governed validation boundaries." })] }),
        /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsxs)(V, {
              href: "#findings",
              variant: "secondary",
              size: "sm",
              children: [
                "Review open findings (",
                s,
                ")"
              ]
            }),
            /* @__PURE__ */ (0, R.jsxs)(V, {
              href: "#high-scale",
              variant: "secondary",
              size: "sm",
              children: [
                "Request SOC-governed test (",
                c,
                " pending)"
              ]
            }),
            m ? /* @__PURE__ */ (0, R.jsx)(V, {
              href: "#notifications",
              variant: "secondary",
              size: "sm",
              children: "Notification rules"
            }) : null,
            h ? /* @__PURE__ */ (0, R.jsx)(V, {
              href: "#release-evidence",
              variant: "ghost",
              size: "sm",
              children: "Release evidence"
            }) : null
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Kill switch" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: d ? "Active" : "Inactive" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Support readiness evidence" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: g ? Y(g, ["status"], "recorded") : "Not indexed" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Escalation state" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.replaceAll("_", " ") })] })
          ]
        })
      ] })
    ]
  });
}
var ka = [
  "waf_posture",
  "external_discovery",
  "connectors",
  "high_scale_program"
], Aa = {
  waf_posture: "WAF posture",
  external_discovery: "External discovery",
  connectors: "Connectors",
  high_scale_program: "High-scale program"
};
function ja(e) {
  return !e || e === "plan only" ? "Plan default" : e.startsWith("plan:") ? `Plan default (${e.slice(5)})` : e;
}
function Ma(e, t, n) {
  let r = n >= 0, i = r && n > 0 ? Math.min(100, Math.round(t / n * 100)) : 0;
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "factor",
    children: [
      /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e }), /* @__PURE__ */ (0, R.jsx)("span", { children: r ? `${t} / ${n}` : `${t} recorded` })] }),
      /* @__PURE__ */ (0, R.jsx)(z, {
        tone: r && t >= n ? "warn" : "info",
        children: r ? `${i}%` : "unlimited"
      }),
      r ? /* @__PURE__ */ (0, R.jsx)(Or, { value: i }) : null
    ]
  }, e);
}
function Na({ data: e }) {
  let t = e.subscriptionSummary, n = ta(t, ["subscription"]), r = ta(t, ["plan"]), i = ta(t, ["account"]), a = ta(t, ["usage"]), o = ta(t, ["support"]), s = ta(r, ["feature_entitlements"]) ?? ta(n, ["feature_entitlements"]), c = ta(n, ["effective_entitlements"]), l = Array.isArray(n?.entitlement_grants) ? n.entitlement_grants : [], u = !!n, d = u ? Y(r ?? {}, ["name"], Y(n ?? {}, ["plan_id"], "Recorded plan")) : "Not configured", f = ea(n, ["limits", "safe_runs_per_hour"], -1), p = $i(a ?? {}, ["safe_runs_started_last_hour"]), m = c?.high_scale_program === !0, h = ea(n, ["limits", "target_groups"], -1), g = $i(a ?? {}, ["target_groups"]), _ = ea(n, ["limits", "users"], -1), v = ea(n, ["limits", "agents"], -1), y = Y(o ?? i ?? {}, ["owner", "support_owner"], "");
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "subscription",
        eyebrow: "Entitlements"
      }),
      u ? null : /* @__PURE__ */ (0, R.jsx)(q, {
        icon: fe,
        title: "No subscription configured for this tenant.",
        body: "AstraNull did not return a tenant subscription from `/v1/subscription/current`. Limits, entitlements, and billing metadata stay hidden until staff provisioning completes. Contact your AstraNull support team through the Support page for provisioning or billing assistance.",
        actionLabel: "Open Support",
        actionHref: "#support"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Plan",
            value: d,
            sub: u ? Y(n ?? {}, ["status"], "status unknown") : "No tenant subscription record",
            icon: M,
            tone: u ? "info" : "muted"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Safe-run cap",
            value: u && f >= 0 ? f : "—",
            sub: u ? `${p} started in the last hour` : "Limits appear after subscription provisioning",
            icon: pe,
            tone: u && f >= 0 && p >= f ? "warn" : u ? "success" : "muted"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "High-scale program",
            value: u ? m ? "Enabled" : "Disabled" : "—",
            sub: u ? "Execution remains SOC-gated" : "Entitlement unavailable without subscription",
            icon: N,
            tone: m ? "warn" : "muted"
          })
        ]
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Contract posture" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Billing metadata, entitlement limits, and account state from `/v1/subscription/current`." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: u ? "kv-list" : "",
          children: u ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Y(n ?? {}, ["status"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Effective" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(n?.effective_at) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Renewal" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(n?.renewal_at) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Data region" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Y(i ?? o ?? {}, ["region"], "unrecorded") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Lifecycle" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Y(i ?? o ?? {}, ["lifecycle_state"], "unrecorded") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Support owner" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Y(i ?? {}, ["support_owner"], y || "unassigned") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Contract ref" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Y(i ?? {}, ["contract_reference"], "unrecorded") })] })
          ] }) : /* @__PURE__ */ (0, R.jsx)(q, {
            icon: M,
            title: "Contract details unavailable.",
            body: "Region, lifecycle, renewal, and support-owner metadata appear after a subscription record exists. Use the Support page to contact your AstraNull support team.",
            actionLabel: "Contact support",
            actionHref: "#support"
          })
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Usage against limits" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Live workspace counts compared to subscription limits." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "factor-list",
          children: u ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            Ma("Target groups", g, h),
            Ma("Users", $i(a ?? {}, ["users"]), _),
            Ma("Agents", $i(a ?? {}, ["agents"]), v),
            Ma("Safe runs / hour", p, f),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "factor",
              children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: "Open findings" }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [$i(a ?? {}, ["open_findings"]), " active records"] })] }), /* @__PURE__ */ (0, R.jsx)(z, {
                tone: $i(a ?? {}, ["open_findings"]) > 0 ? "warn" : "success",
                children: $i(a ?? {}, ["open_findings"])
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "factor",
              children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: "Pending high-scale" }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [$i(a ?? {}, ["pending_high_scale_requests"]), " awaiting SOC workflow"] })] }), /* @__PURE__ */ (0, R.jsx)(z, {
                tone: $i(a ?? {}, ["pending_high_scale_requests"]) > 0 ? "warn" : "muted",
                children: $i(a ?? {}, ["pending_high_scale_requests"])
              })]
            })
          ] }) : /* @__PURE__ */ (0, R.jsx)(q, {
            icon: pe,
            title: "Usage meters unavailable.",
            body: "Safe-run caps, target-group limits, and workspace usage comparisons require a provisioned subscription. Contact support if provisioning should already be complete.",
            actionLabel: "Open Support",
            actionHref: "#support"
          })
        })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Entitlement breakdown" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Plan defaults, staff grants, and effective feature access for this tenant." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: u ? /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "feature",
            label: "Feature",
            render: (e) => {
              let t = Y(e, ["feature"]);
              return Aa[t] ?? t;
            }
          },
          {
            key: "plan",
            label: "Plan default",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: e.plan_enabled === !0 ? "success" : "muted",
              children: e.plan_enabled === !0 ? "enabled" : "disabled"
            })
          },
          {
            key: "effective",
            label: "Effective",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: e.effective_enabled === !0 ? "success" : "warn",
              children: e.effective_enabled === !0 ? "enabled" : "disabled"
            })
          },
          {
            key: "grant",
            label: "Grant source",
            render: (e) => ja(Y(e, ["grant_source"], "plan only"))
          }
        ],
        items: ka.map((e) => {
          let t = l.find((t) => Y(t, ["feature"], "") === e);
          return {
            feature: e,
            plan_enabled: s?.[e] === !0,
            effective_enabled: c?.[e] === !0,
            grant_source: t ? Y(t, ["source"], "staff grant") : "plan only"
          };
        }),
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: "No entitlement features.",
          body: "Plan feature entitlements were not returned by the subscription API."
        })
      }) : /* @__PURE__ */ (0, R.jsx)(q, {
        icon: N,
        title: "No entitlements to display.",
        body: "Feature entitlements are computed after a subscription record exists. Open Support to request plan provisioning or entitlement review.",
        actionLabel: "Open Support",
        actionHref: "#support"
      }) })] })
    ]
  });
}
function Pa({ route: e, data: t, config: n, session: r, onRefresh: i }) {
  let [a, o] = (0, C.useState)(""), [s, c] = (0, C.useState)(""), [l, u] = (0, C.useState)(""), [d, f] = (0, C.useState)(() => Y(t.internalTenants[0] ?? {}, ["tenant_id", "id"], "ten_demo")), [p, m] = (0, C.useState)(null), h = [
    "waf_posture",
    "external_discovery",
    "connectors",
    "high_scale_program"
  ], g = r.principal === "staff", _ = t.internalOverview, v = $i(_ ?? {}, ["pending_signups"]) + $i(_ ?? {}, ["pending_approval_requests"]), y = $i(_ ?? {}, ["tenant_count"], t.internalTenants.length), b = $i(_ ?? {}, ["high_scale_reviews"]);
  async function x(e, t, n) {
    o(e), u(""), c("");
    try {
      let e = await t();
      return c(n), await i(), e;
    } catch (e) {
      let t = e.payload;
      return u(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Staff action failed.")), null;
    } finally {
      o("");
    }
  }
  async function S(e) {
    await x(`approve-signup-${e}`, () => L(n, r, `/internal/admin/signup-requests/${e}/approve`, {
      method: "POST",
      body: { reason: "Approved from React staff console." }
    }), "Signup request approved and tenant provisioned.");
  }
  async function w(e) {
    await x(`reject-signup-${e}`, () => L(n, r, `/internal/admin/signup-requests/${e}/reject`, {
      method: "POST",
      body: { reason: "Rejected from React staff console." }
    }), "Signup request rejected.");
  }
  async function T(e, t) {
    await x(`patch-tenant-${e}`, () => L(n, r, `/internal/admin/tenants/${e}`, {
      method: "PATCH",
      body: {
        lifecycle_state: t,
        reason: `Lifecycle set to ${t} from React staff console.`
      }
    }), `Tenant lifecycle updated to ${t}.`);
  }
  async function E(e, t) {
    await x(`approval-${e}-${t}`, () => L(n, r, `/internal/admin/approval-requests/${e}/decision`, {
      method: "POST",
      body: {
        decision: t,
        reason: `${t} from React staff console.`
      }
    }), `Approval request ${t}d.`);
  }
  (0, C.useEffect)(() => {
    if (!g || !d) {
      m(null);
      return;
    }
    let e = !1;
    return L(n, r, `/internal/admin/tenants/${encodeURIComponent(d)}/subscription`).then((t) => {
      e || m(t);
    }).catch(() => {
      e || m(null);
    }), () => {
      e = !0;
    };
  }, [
    n,
    r,
    d,
    g,
    t.internalTenants
  ]);
  async function D(e) {
    e.preventDefault();
    let t = new FormData(e.currentTarget), i = String(t.get("feature") ?? "").trim(), a = String(t.get("enabled") ?? "true") === "true", o = String(t.get("reason") ?? "").trim();
    if (!d || !i) {
      u("Select a tenant and feature before granting entitlements.");
      return;
    }
    await x(`entitlement-${d}-${i}`, () => L(n, r, `/internal/admin/tenants/${encodeURIComponent(d)}/entitlements`, {
      method: "POST",
      body: {
        feature: i,
        enabled: a,
        reason: o || `Entitlement ${a ? "granted" : "revoked"} from React staff console.`
      }
    }), `${i} entitlement ${a ? "granted" : "revoked"} for ${d}.`);
  }
  let O = ta(p, ["effective_entitlements"]) ?? ta(p, ["subscription", "effective_entitlements"]);
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: e,
        eyebrow: e === "internal-soc" ? "Staff SOC surface" : "Staff-only surface"
      }),
      (s || l) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: l ? "form-banner error" : "form-banner",
        children: l || s
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Review queue",
            value: v,
            sub: "Signups plus internal approvals",
            icon: se,
            tone: v > 0 ? "warn" : "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Managed tenants",
            value: y,
            sub: "Internal management directory",
            icon: ke,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "SOC reviews",
            value: b,
            sub: "High-scale requests awaiting staff workflow",
            icon: N,
            tone: b > 0 ? "warn" : "success"
          })
        ]
      }),
      g ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Signup queue" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Requests from the staff-only signup review API." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
            columns: [
              {
                key: "org",
                label: "Organization",
                render: (e) => Y(e, ["organization_name", "id"])
              },
              {
                key: "state",
                label: "State",
                render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                  tone: ["submitted", "under_review"].includes(Y(e, ["state"])) ? "warn" : "info",
                  children: Y(e, ["state"])
                })
              },
              {
                key: "plan",
                label: "Plan",
                render: (e) => Y(e, ["requested_plan"])
              },
              {
                key: "created",
                label: "Created",
                render: (e) => I(e.created_at)
              },
              {
                key: "actions",
                label: "Actions",
                render: (e) => {
                  let t = Y(e, ["id"], ""), n = Y(e, ["state"], "");
                  return ["submitted", "under_review"].includes(n) ? /* @__PURE__ */ (0, R.jsxs)("div", {
                    className: "row-actions",
                    children: [/* @__PURE__ */ (0, R.jsx)(B, {
                      size: "sm",
                      variant: "secondary",
                      disabled: a !== "",
                      onClick: () => void S(t),
                      children: "Approve"
                    }), /* @__PURE__ */ (0, R.jsx)(B, {
                      size: "sm",
                      variant: "danger",
                      disabled: a !== "",
                      onClick: () => void w(t),
                      children: "Reject"
                    })]
                  }) : "—";
                }
              }
            ],
            items: t.internalSignupRequests,
            empty: /* @__PURE__ */ (0, R.jsx)(q, {
              icon: se,
              title: "No signup requests.",
              body: "Reviewed account intake records will appear here after customers submit requests."
            })
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Tenant directory" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Managed tenant account and subscription metadata." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
            columns: [
              {
                key: "tenant",
                label: "Tenant",
                render: (e) => Y(e, ["name", "tenant_id"])
              },
              {
                key: "state",
                label: "Lifecycle",
                render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                  tone: Y(e, ["lifecycle_state"]) === "active" ? "success" : "warn",
                  children: Y(e, ["lifecycle_state"])
                })
              },
              {
                key: "plan",
                label: "Plan",
                render: (e) => Y(e, ["plan_id"])
              },
              {
                key: "owner",
                label: "Support owner",
                render: (e) => Y(e, ["support_owner"], "unassigned")
              },
              {
                key: "actions",
                label: "Actions",
                render: (e) => {
                  let t = Y(e, ["tenant_id", "id"], ""), n = Y(e, ["lifecycle_state"], "active");
                  return /* @__PURE__ */ (0, R.jsxs)("div", {
                    className: "row-actions",
                    children: [
                      /* @__PURE__ */ (0, R.jsx)(V, {
                        size: "sm",
                        variant: "secondary",
                        href: Mr("tenant-detail", t),
                        children: "Detail"
                      }),
                      n === "active" ? null : /* @__PURE__ */ (0, R.jsx)(B, {
                        size: "sm",
                        variant: "secondary",
                        disabled: a !== "",
                        onClick: () => void T(t, "active"),
                        children: "Activate"
                      }),
                      n === "active" ? /* @__PURE__ */ (0, R.jsx)(B, {
                        size: "sm",
                        variant: "danger",
                        disabled: a !== "",
                        onClick: () => void T(t, "suspended"),
                        children: "Suspend"
                      }) : null
                    ]
                  });
                }
              }
            ],
            items: t.internalTenants,
            empty: /* @__PURE__ */ (0, R.jsx)(q, {
              icon: ke,
              title: "No managed tenants.",
              body: "Provisioned tenants appear here after staff approval creates account records."
            })
          }) })] })]
        }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Approval requests" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Unified internal approvals, including subscription exceptions." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
            columns: [
              {
                key: "kind",
                label: "Kind",
                render: (e) => Y(e, ["kind"])
              },
              {
                key: "state",
                label: "State",
                render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                  tone: ["submitted", "under_review"].includes(Y(e, ["state"])) ? "warn" : "success",
                  children: Y(e, ["state"])
                })
              },
              {
                key: "tenant",
                label: "Tenant",
                render: (e) => Y(e, ["tenant_id"])
              },
              {
                key: "created",
                label: "Created",
                render: (e) => I(e.created_at)
              },
              {
                key: "actions",
                label: "Actions",
                render: (e) => {
                  let t = Y(e, ["id"], ""), n = Y(e, ["state"], "");
                  return ["submitted", "under_review"].includes(n) ? /* @__PURE__ */ (0, R.jsxs)("div", {
                    className: "row-actions",
                    children: [/* @__PURE__ */ (0, R.jsx)(B, {
                      size: "sm",
                      variant: "secondary",
                      disabled: a !== "",
                      onClick: () => void E(t, "approve"),
                      children: "Approve"
                    }), /* @__PURE__ */ (0, R.jsx)(B, {
                      size: "sm",
                      variant: "danger",
                      disabled: a !== "",
                      onClick: () => void E(t, "reject"),
                      children: "Reject"
                    })]
                  }) : "—";
                }
              }
            ],
            items: t.internalApprovalRequests,
            empty: /* @__PURE__ */ (0, R.jsx)(q, {
              icon: N,
              title: "No internal approvals.",
              body: "Pending approval records will appear here when backend workflows create them."
            })
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Internal audit" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Recent staff actions from the internal audit API." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
            columns: [
              {
                key: "action",
                label: "Action",
                render: (e) => Y(e, ["action"])
              },
              {
                key: "staff",
                label: "Staff",
                render: (e) => Y(e, ["staff_id"])
              },
              {
                key: "tenant",
                label: "Tenant",
                render: (e) => Y(e, ["tenant_id"])
              },
              {
                key: "created",
                label: "Created",
                render: (e) => I(e.created_at)
              }
            ],
            items: t.internalAudit,
            empty: /* @__PURE__ */ (0, R.jsx)(q, {
              icon: j,
              title: "No internal audit events.",
              body: "Staff decisions and support actions will be listed after they are recorded."
            })
          }) })] })]
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Support owner assignment" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Patch tenant support owner through `/internal/admin/tenants/:id`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: (e) => {
            e.preventDefault();
            let t = String(new FormData(e.currentTarget).get("support_owner") ?? "").trim();
            !d || !t || x(`support-owner-${d}`, () => L(n, r, `/internal/admin/tenants/${encodeURIComponent(d)}`, {
              method: "PATCH",
              body: {
                support_owner: t,
                reason: "Support owner updated from React staff console."
              }
            }), `Support owner updated for ${d}.`);
          },
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Tenant" }), /* @__PURE__ */ (0, R.jsx)("select", {
              name: "tenant_id",
              value: d,
              onChange: (e) => f(e.target.value),
              children: t.internalTenants.map((e) => {
                let t = Y(e, ["tenant_id", "id"], "");
                return /* @__PURE__ */ (0, R.jsx)("option", {
                  value: t,
                  children: Y(e, ["name", "tenant_id"], t)
                }, t);
              })
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Support owner" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "support_owner",
                placeholder: "owner@customer.example",
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: a !== "",
                children: "Assign support owner"
              })
            })
          ]
        }) })] }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Entitlement grants" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Grant or revoke plan feature entitlements through `/internal/admin/tenants/:id/entitlements`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "product-form",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Tenant" }), /* @__PURE__ */ (0, R.jsx)("select", {
              value: d,
              onChange: (e) => f(e.target.value),
              children: t.internalTenants.map((e) => {
                let t = Y(e, ["tenant_id", "id"], "");
                return /* @__PURE__ */ (0, R.jsx)("option", {
                  value: t,
                  children: Y(e, ["name", "tenant_id"], t)
                }, t);
              })
            })] }),
            O ? /* @__PURE__ */ (0, R.jsx)("div", {
              className: "kv-list",
              children: h.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: e }), /* @__PURE__ */ (0, R.jsx)("strong", { children: O[e] === !0 ? "enabled" : "disabled" })] }, e))
            }) : /* @__PURE__ */ (0, R.jsx)("p", {
              className: "muted",
              children: "Effective entitlements load after tenant subscription is fetched."
            }),
            /* @__PURE__ */ (0, R.jsxs)("form", {
              className: "product-form",
              onSubmit: D,
              children: [
                /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Feature" }), /* @__PURE__ */ (0, R.jsx)("select", {
                  name: "feature",
                  defaultValue: "waf_posture",
                  children: h.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                    value: e,
                    children: e
                  }, e))
                })] }),
                /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Action" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                  name: "enabled",
                  defaultValue: "true",
                  children: [/* @__PURE__ */ (0, R.jsx)("option", {
                    value: "true",
                    children: "Grant / enable"
                  }), /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "false",
                    children: "Revoke / disable"
                  })]
                })] }),
                /* @__PURE__ */ (0, R.jsxs)("label", {
                  className: "full",
                  children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Reason" }), /* @__PURE__ */ (0, R.jsx)("input", {
                    name: "reason",
                    placeholder: "Verified plan exception",
                    required: !0
                  })]
                }),
                /* @__PURE__ */ (0, R.jsx)("div", {
                  className: "form-actions full",
                  children: /* @__PURE__ */ (0, R.jsx)(B, {
                    type: "submit",
                    disabled: a !== "" || !d,
                    children: "Apply entitlement"
                  })
                })
              ]
            })
          ]
        })] })
      ] }) : /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Staff session required" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Internal management data is only fetched after staff authentication." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(q, {
        icon: je,
        title: "No staff principal.",
        body: "Use the staff sign-in surface to load internal management queues and audit records.",
        actionLabel: "Open staff login",
        actionHref: "/internal/admin/login"
      }) })] })
    ]
  });
}
//#endregion
//#region apps/web/react/src/pages/detail-pages.tsx
function Z(e, t, n = "—") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Fa(e, t, n = "—") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
function Ia(e, t, n = 0) {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return typeof r == "number" && Number.isFinite(r) ? r : n;
}
function La(e, t) {
  let n = e;
  for (let e of t) {
    if (!n || typeof n != "object" || Array.isArray(n)) return [];
    n = n[e];
  }
  return Array.isArray(n) ? n : [];
}
function Ra(e, t) {
  let n = e;
  for (let e of t) {
    if (!n || typeof n != "object" || Array.isArray(n)) return null;
    n = n[e];
  }
  return n && typeof n == "object" && !Array.isArray(n) ? n : null;
}
function za(e) {
  return e.replace(/_/g, " ");
}
function Ba(e, t, n) {
  if (e === "run-detail") {
    let e = Ia(t, [
      "verdict",
      "placement_confidence",
      "score"
    ], NaN), n = Fa(t, ["verdict", "verdict"], Z(t, ["status"], "pending")), r = [];
    return Number.isFinite(e) && r.push({
      label: "Placement confidence",
      body: Fa(t, [
        "verdict",
        "placement_confidence",
        "level"
      ], "Recorded from verdict evidence."),
      value: Math.round(e)
    }), n !== "pending" && r.push({
      label: "Verdict outcome",
      body: Fa(t, ["verdict", "explanation"], Fa(t, ["verdict", "conclusion"], "Final verdict from `/v1/test-runs/:id`.")),
      value: n === "pass" ? 100 : n === "fail" ? 65 : 50
    }), r;
  }
  if (e === "waf-asset-detail") {
    let e = La(t, ["current_posture", "risk_factors"]);
    if (e.length > 0) return e.map((e) => ({
      label: za(Z(e, ["factor"], "risk factor")),
      body: Z(e, ["value"], "Recorded posture risk signal."),
      value: Math.min(100, Math.max(0, Ia(e, ["contribution"], 0)))
    }));
    let n = Ia(t, ["effectiveness", "scenario_pass_rate"], NaN);
    return Number.isFinite(n) && n > 0 ? [{
      label: "Scenario pass rate",
      body: "Latest effectiveness summary from `/v1/waf/assets/:id`.",
      value: Math.round(n)
    }] : [];
  }
  if (e === "cve-detail") {
    let e = Ra(t, ["triage_result"]), r = [];
    e && typeof e.score == "number" && Number.isFinite(e.score) && r.push({
      label: "Triage score",
      body: Z(e, ["summary"], "Exposure triage from `/v1/waf/cve-pipeline/:id/triage`."),
      value: Math.min(100, Math.max(0, Math.round(e.score)))
    });
    let i = e?.factors;
    if (i && typeof i == "object" && !Array.isArray(i)) for (let [e, t] of Object.entries(i)) t === !0 && r.push({
      label: za(e),
      body: "Boolean triage factor returned by the CVE pipeline API.",
      value: 100
    });
    return n.cveMatches.length > 0 && r.push({
      label: "Declared asset matches",
      body: `${n.cveMatches.length} metadata-only matches from /v1/waf/cve-pipeline/:id/match.`,
      value: Math.min(100, n.cveMatches.length * 20)
    }), r;
  }
  if (e === "supply-chain-detail") {
    let e = Ia(t, ["confidence"], NaN);
    if (Number.isFinite(e)) return [{
      label: "Exposure confidence",
      body: `${Z(t, ["exposure_type"])} on ${Z(t, ["hostname"])}.`,
      value: Math.round(e * 100)
    }];
  }
  return [];
}
function Va({ factors: e, emptyTitle: t = "No evidence factors yet.", emptyBody: n = "Factors appear after the backend returns entity-specific readiness or posture signals." }) {
  return e.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
    icon: j,
    title: t,
    body: n
  }) : /* @__PURE__ */ (0, R.jsx)("div", {
    className: "factor-list",
    children: e.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "factor",
      children: [
        /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.label }), /* @__PURE__ */ (0, R.jsx)("span", { children: e.body })] }),
        /* @__PURE__ */ (0, R.jsxs)(z, {
          tone: hn(e.value),
          children: [e.value, "%"]
        }),
        /* @__PURE__ */ (0, R.jsx)(Or, { value: e.value })
      ]
    }, e.label))
  });
}
function Ha({ items: e }) {
  return e.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
    className: "muted",
    children: "No timeline milestones recorded for this entity."
  }) : /* @__PURE__ */ (0, R.jsx)("div", {
    className: "timeline-list",
    children: e.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: t + 1 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e.label }), /* @__PURE__ */ (0, R.jsx)("p", { children: I(e.at) })] })] }, `${e.label}-${t}`))
  });
}
function Ua(e, t, n, r, i) {
  let [a, o] = (0, C.useState)(i), [s, c] = (0, C.useState)(""), [l, u] = (0, C.useState)(e && !!r);
  return (0, C.useEffect)(() => {
    if (!e || !r) {
      o(i), u(!1);
      return;
    }
    let a = !1;
    return u(!0), c(""), L(t, n, r).then((e) => {
      a || o(e);
    }).catch((e) => {
      a || (o(i), c(e instanceof Error ? e.message : "Could not load entity detail."));
    }).finally(() => {
      a || u(!1);
    }), () => {
      a = !0;
    };
  }, [
    t,
    n,
    r,
    e,
    i
  ]), {
    detail: a,
    error: s,
    loading: l
  };
}
function Wa(e, t, n, r, i, a) {
  let [o, s] = (0, C.useState)(a), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(e && !!i);
  return (0, C.useEffect)(() => {
    if (!e || !i) {
      s(a), d(!1);
      return;
    }
    let o = !1;
    return d(!0), l(""), L(t, n, r).then((e) => {
      if (o) return;
      let t = (Array.isArray(e.items) ? e.items : []).find((e) => Z(e, ["id"], "") === i) ?? null;
      s(t ?? a), !t && !a && l("Entity not found in tenant list APIs.");
    }).catch((e) => {
      o || (s(a), l(e instanceof Error ? e.message : "Could not load entity detail."));
    }).finally(() => {
      o || d(!1);
    }), () => {
      o = !0;
    };
  }, [
    t,
    n,
    r,
    e,
    i,
    a
  ]), {
    detail: o,
    error: c,
    loading: u
  };
}
function Ga({ entity: e, entityId: t, data: n, config: r, session: i, onRefresh: a, runEvents: o, loading: s, loadError: c }) {
  let [l, u] = (0, C.useState)("summary"), [d, f] = (0, C.useState)(""), [p, m] = (0, C.useState)(""), [h, g] = (0, C.useState)(""), _ = _i("run-detail").map((e) => ({
    id: e.id,
    label: e.label
  })), v = e.verdict, y = o.filter((e) => Z(e, ["signal_type"]) === "probe_result"), b = o.filter((e) => ["agent_observation", "agent_no_observation"].includes(Z(e, ["signal_type"]))), x = n.evidence.filter((e) => Z(e, ["test_run_id"], "") === t), S = n.findings.filter((e) => Z(e, ["test_run_id"], "") === t), w = Z(e, ["status"], ""), T = [
    "planned",
    "running",
    "collecting"
  ].includes(w);
  async function E(e, t, n) {
    f(e), g(""), m("");
    try {
      await t(), m(n), await a();
    } catch (e) {
      g(e instanceof Error ? e.message : "Action failed.");
    } finally {
      f("");
    }
  }
  let D = [
    {
      label: "Run created",
      at: e.created_at
    },
    {
      label: "Run started",
      at: e.started_at
    },
    {
      label: "Probe window",
      at: e.probe_started_at ?? e.updated_at
    },
    {
      label: "Verdict recorded",
      at: Fa(e, ["verdict", "finalized_at"], "") || e.completed_at
    }
  ].filter((e) => e.at);
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "run-detail",
        eyebrow: "Entity detail"
      }),
      (p || h || c || s) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: h || c ? "form-banner error" : "form-banner",
        children: h || c || p || "Loading run detail..."
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: l,
        options: _,
        onChange: u,
        className: "tabs-wrap"
      }),
      l === "summary" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: t }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        Z(e, ["check_id"]),
        " · ",
        Z(e, ["status"]),
        " · verdict ",
        Fa(e, ["verdict", "verdict"], "pending")
      ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Check" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["check_id"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["target_group_id"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["target_id"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Vector" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["vector_family"], "—") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Safety" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["safety_class"], "—") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Verdict" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(v ?? {}, ["verdict"], "pending") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Placement confidence" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Fa(v ?? {}, ["placement_confidence", "level"], "unknown") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Confidence" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(v ?? {}, ["confidence"], "—") })] })
          ]
        }),
        /* @__PURE__ */ (0, R.jsx)(Zr, {
          detail: e,
          events: o
        }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          style: { marginTop: "1rem" },
          children: [/* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: "#runs",
            children: "Open test runs"
          }), T ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "danger",
            disabled: d !== "",
            onClick: () => void E(`cancel-${t}`, () => L(r, i, `/v1/test-runs/${t}/cancel`, { method: "POST" }), "Run cancelled."),
            children: "Cancel"
          }), /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "ghost",
            disabled: d !== "",
            onClick: () => void E(`finalize-${t}`, () => L(r, i, `/v1/test-runs/${t}/finalize`, { method: "POST" }), "Run finalized after observation window."),
            children: "Finalize"
          })] }) : null]
        })
      ] })] }) : null,
      l === "timeline" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Timeline" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Ordered run lifecycle from scheduling through final verdict." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
        /* @__PURE__ */ (0, R.jsx)(Ha, { items: D }),
        /* @__PURE__ */ (0, R.jsx)(Xr, { events: o }),
        o.length > 0 ? /* @__PURE__ */ (0, R.jsx)("div", {
          className: "timeline-list",
          children: o.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: t + 1 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["signal_type", "type"]) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
            I(e.timestamp ?? e.created_at),
            " — ",
            Z(e, ["source"], "system")
          ] })] })] }, Z(e, ["id"], String(t))))
        }) : /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: "No run events recorded yet."
        })
      ] })] }) : null,
      l === "probe-results" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Probe results" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Outside observations from bounded probes." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: y.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted",
        children: "No probe_result events for this run."
      }) : /* @__PURE__ */ (0, R.jsx)("div", {
        className: "kv-list",
        children: y.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: I(e.timestamp ?? e.created_at) }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Fa(e, ["metadata", "external_result"], Z(e, ["external_result"], Z(e, ["source"], "probe_result"))) })] }, Z(e, ["id"], String(t))))
      }) })] }) : null,
      l === "agent-observations" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent observations" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Inside observations from outbound-only canaries." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: b.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted",
        children: "No agent observation events for this run."
      }) : /* @__PURE__ */ (0, R.jsx)("div", {
        className: "kv-list",
        children: b.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Z(e, ["signal_type"]) }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [
          Z(e, ["agent_id"], Z(e, ["source"], "agent")),
          " · ",
          I(e.timestamp ?? e.created_at)
        ] })] }, Z(e, ["id"], String(t))))
      }) })] }) : null,
      l === "correlation" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Correlation" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Truth table and verdict explanation from observed facts." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [/* @__PURE__ */ (0, R.jsx)(Jr, {
        detail: e,
        events: o
      }), /* @__PURE__ */ (0, R.jsx)(Yr, { detail: e })] })] }) : null,
      l === "evidence" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Evidence" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Custody-ready artifacts generated by this run." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [x.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted",
        children: "No evidence records linked to this run yet."
      }) : /* @__PURE__ */ (0, R.jsx)("div", {
        className: "kv-list",
        children: x.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Z(e, ["kind", "signal_type"], "evidence") }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["id"]) })] }, Z(e, ["id"], "")))
      }), S.length > 0 ? /* @__PURE__ */ (0, R.jsx)("div", {
        className: "row-actions",
        style: { marginTop: "1rem" },
        children: /* @__PURE__ */ (0, R.jsx)(V, {
          size: "sm",
          variant: "ghost",
          href: "#findings",
          children: "Open findings"
        })
      }) : null] })] }) : null,
      l === "events" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Raw events" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Sanitized event envelope review from `/v1/test-runs/:id/events`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: o.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted",
        children: "No events recorded yet."
      }) : /* @__PURE__ */ (0, R.jsx)("div", {
        className: "timeline-list",
        children: o.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: t + 1 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["signal_type", "type"]) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
          I(e.timestamp ?? e.created_at),
          " · ",
          Z(e, ["source"], "system"),
          " · ",
          Z(e, ["agent_id"], "—")
        ] })] })] }, Z(e, ["id"], String(t))))
      }) })] }) : null
    ]
  });
}
var Ka = [
  "waf_posture",
  "external_discovery",
  "connectors",
  "high_scale_program"
];
function qa({ entityId: e, detail: t, data: n, config: r, session: i, onRefresh: a, loading: o, loadError: s }) {
  let [c, l] = (0, C.useState)("overview"), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(""), [m, h] = (0, C.useState)(""), [g, _] = (0, C.useState)(null), [v, y] = (0, C.useState)(t);
  (0, C.useEffect)(() => {
    y(t);
  }, [t]);
  let b = v, x = Ra(b, ["tenant"]) ?? b, S = Ra(b, ["account"]), w = Ra(b, ["subscription"]) ?? g, T = La(b, ["users"]), E = Ra(b, ["signup_request"]), D = La(b, ["recent_tenant_audit"]), O = n.internalApprovalRequests.filter((t) => Z(t, ["tenant_id"], "") === e), ee = Z(S, ["lifecycle_state"], "active"), te = _i("tenant-detail").map((e) => ({
    id: e.id,
    label: e.label
  })), ne = Ra(w, ["effective_entitlements"]) ?? Ra(g, ["effective_entitlements"]);
  (0, C.useEffect)(() => {
    if (!e || i.principal !== "staff") {
      _(null);
      return;
    }
    let t = !1;
    return L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}/subscription`).then((e) => {
      t || _(e);
    }).catch(() => {
      t || _(null);
    }), () => {
      t = !0;
    };
  }, [
    r,
    i,
    e,
    b
  ]);
  async function re() {
    let [t, n] = await Promise.all([L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}`), L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}/subscription`).catch(() => null)]);
    y(t), n && _(n);
  }
  async function ie(e, t, n) {
    d(e), h(""), p("");
    try {
      let e = await t();
      return p(n), await re(), await a(), e;
    } catch (e) {
      let t = e.payload;
      return h(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Staff action failed.")), null;
    } finally {
      d("");
    }
  }
  async function ae(t) {
    await ie(`lifecycle-${e}-${t}`, () => L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}`, {
      method: "PATCH",
      body: {
        lifecycle_state: t,
        reason: `Lifecycle set to ${t} from tenant detail.`
      }
    }), `Tenant lifecycle updated to ${t}.`);
  }
  async function oe(t) {
    t.preventDefault();
    let n = String(new FormData(t.currentTarget).get("support_owner") ?? "").trim();
    n && await ie(`support-owner-${e}`, () => L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}`, {
      method: "PATCH",
      body: {
        support_owner: n,
        reason: "Support owner updated from tenant detail."
      }
    }), "Support owner updated.");
  }
  async function k(t) {
    t.preventDefault();
    let n = new FormData(t.currentTarget), a = String(n.get("feature") ?? "").trim(), o = String(n.get("enabled") ?? "true") === "true", s = String(n.get("reason") ?? "").trim();
    a && await ie(`entitlement-${e}-${a}`, () => L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}/entitlements`, {
      method: "POST",
      body: {
        feature: a,
        enabled: o,
        reason: s || `Entitlement ${o ? "granted" : "revoked"} from tenant detail.`
      }
    }), `${a} entitlement ${o ? "granted" : "revoked"}.`);
  }
  async function A(t) {
    await ie(`resend-${e}-${t}`, () => L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}/users/${encodeURIComponent(t)}/resend-invite`, {
      method: "POST",
      body: {}
    }), "Invite resend recorded.");
  }
  async function ce(t) {
    await ie(`disable-${e}-${t}`, () => L(r, i, `/internal/admin/tenants/${encodeURIComponent(e)}/users/${encodeURIComponent(t)}/disable`, {
      method: "POST",
      body: { reason: "Disabled from tenant detail." }
    }), "User disabled.");
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "tenant-detail",
        eyebrow: "Staff tenant operations"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "page-head",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("h2", { children: Z(x, ["name"], e) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
          /* @__PURE__ */ (0, R.jsx)("code", { children: e }),
          " · ",
          ee,
          " · plan ",
          Z(w, ["plan_id"], "—"),
          " · ",
          T.length,
          " users"
        ] })] }), /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: "#admin",
            children: "Staff admin"
          }), ee === "active" ? /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "danger",
            disabled: u !== "",
            onClick: () => void ae("suspended"),
            children: "Suspend"
          }) : /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            disabled: u !== "",
            onClick: () => void ae("active"),
            children: "Activate"
          })]
        })]
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid four",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Lifecycle",
            value: ee,
            sub: "Account state from internal management API",
            icon: N,
            tone: ee === "active" ? "success" : "warn"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Users",
            value: T.length,
            sub: "Tenant-scoped identities",
            icon: Ne,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Approvals",
            value: O.length,
            sub: "Internal requests for this tenant",
            icon: se,
            tone: O.length > 0 ? "warn" : "muted"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Audit events",
            value: D.length,
            sub: "Recent tenant-scoped audit entries",
            icon: j,
            tone: "muted"
          })
        ]
      }),
      (f || m || s || o) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: m || s ? "form-banner error" : "form-banner",
        children: m || s || f || "Loading tenant detail..."
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: c,
        options: te,
        onChange: l,
        className: "tabs-wrap"
      }),
      c === "overview" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Tenant administration" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "From `GET /internal/admin/tenants/:id`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Tenant ID" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: /* @__PURE__ */ (0, R.jsx)("code", { children: e }) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(x, ["name"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Lifecycle" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ee })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Region" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(S, ["region"], "—") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Support owner" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(S, ["support_owner"], "unassigned") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Created" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(x?.created_at) })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Subscription" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Plan and entitlement summary for this tenant." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Plan" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(w, ["plan_id"], "—") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(w, ["status"], "—") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Effective from" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(w?.effective_from ?? w?.created_at) })] }),
            ne ? Ka.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: e }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ne[e] === !0 ? "enabled" : "disabled" })] }, e)) : /* @__PURE__ */ (0, R.jsx)("p", {
              className: "muted",
              children: "Subscription entitlements load from the tenant subscription API."
            })
          ]
        })] })]
      }) : null,
      c === "signup-queue" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Provisioning signup" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Signup request that created this tenant, if recorded." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: E ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "kv-list",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Request ID" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: /* @__PURE__ */ (0, R.jsx)("code", { children: Z(E, ["id"]) }) })] }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "State" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(E, ["state"]) })] })]
      }) : /* @__PURE__ */ (0, R.jsx)(q, {
        icon: se,
        title: "No linked signup request.",
        body: "Tenants provisioned outside the signup queue may not have a signup_request reference.",
        actionLabel: "Open staff admin",
        actionHref: "#admin"
      }) })] }) : null,
      c === "tenants" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Tenant users" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Resend invites or disable users through staff support APIs." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "email",
            label: "Email",
            render: (e) => Z(e, ["email"])
          },
          {
            key: "role",
            label: "Role",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: "info",
              children: Z(e, ["role"])
            })
          },
          {
            key: "status",
            label: "Status",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: Z(e, ["status"]) === "active" ? "success" : "warn",
              children: Z(e, ["status"])
            })
          },
          {
            key: "actions",
            label: "Actions",
            render: (e) => {
              let t = Z(e, ["id"], "");
              return Z(e, ["status"]) === "disabled" ? "—" : /* @__PURE__ */ (0, R.jsxs)("div", {
                className: "row-actions",
                children: [/* @__PURE__ */ (0, R.jsx)(B, {
                  size: "sm",
                  variant: "ghost",
                  disabled: u !== "",
                  onClick: () => void A(t),
                  children: "Resend invite"
                }), /* @__PURE__ */ (0, R.jsx)(B, {
                  size: "sm",
                  variant: "danger",
                  disabled: u !== "",
                  onClick: () => void ce(t),
                  children: "Disable"
                })]
              });
            }
          }
        ],
        items: T,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: Ne,
          title: "No users on this tenant.",
          body: "Provisioned tenants include an initial owner invite."
        })
      }) })] }), /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Support owner" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Patch through `PATCH /internal/admin/tenants/:id`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: oe,
          children: [/* @__PURE__ */ (0, R.jsxs)("label", {
            className: "full",
            children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Support owner" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "support_owner",
              defaultValue: Z(S, ["support_owner"], ""),
              placeholder: "owner@customer.example",
              required: !0
            })]
          }), /* @__PURE__ */ (0, R.jsx)("div", {
            className: "form-actions full",
            children: /* @__PURE__ */ (0, R.jsx)(B, {
              type: "submit",
              disabled: u !== "",
              children: "Save support owner"
            })
          })]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Entitlement grants" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Grant or revoke features through `POST /internal/admin/tenants/:id/entitlements`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: k,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Feature" }), /* @__PURE__ */ (0, R.jsx)("select", {
              name: "feature",
              defaultValue: "waf_posture",
              children: Ka.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: e,
                children: e
              }, e))
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Action" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "enabled",
              defaultValue: "true",
              children: [/* @__PURE__ */ (0, R.jsx)("option", {
                value: "true",
                children: "Grant / enable"
              }), /* @__PURE__ */ (0, R.jsx)("option", {
                value: "false",
                children: "Revoke / disable"
              })]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Reason" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "reason",
                placeholder: "Verified plan exception",
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: u !== "",
                children: "Apply entitlement"
              })
            })
          ]
        }) })] })]
      })] }) : null,
      c === "approvals" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Approval requests" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Internal approvals scoped to this tenant." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "kind",
            label: "Kind",
            render: (e) => Z(e, ["kind"])
          },
          {
            key: "state",
            label: "State",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: "warn",
              children: Z(e, ["state"])
            })
          },
          {
            key: "created",
            label: "Created",
            render: (e) => I(e.created_at)
          }
        ],
        items: O,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: "No approval requests.",
          body: "Pending internal approvals for this tenant will appear here.",
          actionLabel: "Open staff admin",
          actionHref: "#admin"
        })
      }) })] }) : null,
      c === "audit" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Internal audit" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Recent tenant-scoped audit entries from tenant detail payload." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "action",
            label: "Action",
            render: (e) => Z(e, ["action"])
          },
          {
            key: "actor",
            label: "Actor",
            render: (e) => Z(e, ["actor_user_id", "staff_id"], "—")
          },
          {
            key: "resource",
            label: "Resource",
            render: (e) => `${Z(e, ["resource_type"])}:${Z(e, ["resource_id"], "—")}`
          },
          {
            key: "created",
            label: "Created",
            render: (e) => I(e.created_at)
          }
        ],
        items: D,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: j,
          title: "No audit events yet.",
          body: "Tenant security-relevant actions appear after staff or customer mutations are recorded."
        })
      }) })] }) : null
    ]
  });
}
function Ja({ entity: e, entityId: t, data: n, config: r, session: i, onRefresh: a, loading: o, loadError: s }) {
  let [c, l] = (0, C.useState)("overview"), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(""), [m, h] = (0, C.useState)(""), g = La(e, ["targets"]), _ = n.runs.filter((e) => Z(e, ["target_group_id"], "") === t), v = n.findings.filter((e) => Z(e, ["target_group_id"], "") === t), y = n.agents.filter((e) => Z(e, ["target_group_id"], "") === t), b = n.testPolicies.filter((e) => Z(e, ["target_group_id"], "") === t), x = v.filter((e) => Z(e, ["status"], "open") === "open"), S = [..._].sort((e, t) => {
    let n = String(e.updated_at ?? e.created_at ?? "");
    return String(t.updated_at ?? t.created_at ?? "").localeCompare(n);
  })[0] ?? null, w = _i("target-group-detail").map((e) => ({
    id: e.id,
    label: e.label
  })), T = [
    {
      key: "kind",
      label: "Type",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Z(e, ["kind"])
      })
    },
    {
      key: "value",
      label: "Target",
      render: (e) => Z(e, ["value"])
    },
    {
      key: "expected",
      label: "Expected behavior",
      render: (e) => vn(Z(e, ["expected_behavior"], ""))
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    }
  ], E = [
    {
      key: "id",
      label: "Run",
      render: (e) => /* @__PURE__ */ (0, R.jsx)("code", { children: Z(e, ["id"]) })
    },
    {
      key: "check",
      label: "Check",
      render: (e) => Z(e, ["check_id"])
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Z(e, ["status"], "pending")
      })
    },
    {
      key: "when",
      label: "When",
      render: (e) => I(e.updated_at ?? e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(V, {
        size: "sm",
        variant: "ghost",
        href: Mr("run-detail", Z(e, ["id"], "")),
        children: "Open"
      })
    }
  ], D = [
    {
      key: "id",
      label: "Finding",
      render: (e) => /* @__PURE__ */ (0, R.jsx)("code", { children: Z(e, ["id"]) })
    },
    {
      key: "severity",
      label: "Severity",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "danger",
        children: Z(e, ["severity"], "unknown")
      })
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "warn",
        children: Z(e, ["status"], "open")
      })
    },
    {
      key: "summary",
      label: "Summary",
      render: (e) => Z(e, ["summary", "title"], "—")
    }
  ], ee = [
    {
      key: "hostname",
      label: "Agent",
      render: (e) => Z(e, [
        "hostname",
        "name",
        "id"
      ])
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "success",
        children: Z(e, ["status"], "unknown")
      })
    },
    {
      key: "heartbeat",
      label: "Last heartbeat",
      render: (e) => I(e.last_heartbeat_at ?? e.updated_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(V, {
        size: "sm",
        variant: "ghost",
        href: Mr("agent-detail", Z(e, ["id"], "")),
        children: "Detail"
      })
    }
  ], te = [
    {
      key: "id",
      label: "Policy",
      render: (e) => /* @__PURE__ */ (0, R.jsx)("code", { children: Z(e, ["id"]) })
    },
    {
      key: "check",
      label: "Check",
      render: (e) => Z(e, ["check_id"])
    },
    {
      key: "cadence",
      label: "Cadence",
      render: (e) => Z(e, ["cadence", "schedule"], "manual")
    },
    {
      key: "enabled",
      label: "Enabled",
      render: (e) => e.enabled === !1 ? "no" : "yes"
    }
  ];
  async function ne(e, t, n) {
    d(e), h(""), p("");
    try {
      await t(), p(n), await a();
    } catch (e) {
      let t = e.payload;
      h(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Action failed."));
    } finally {
      d("");
    }
  }
  async function ie(n) {
    n.preventDefault();
    let a = new FormData(n.currentTarget);
    await ne(`patch-target-group-${t}`, () => L(r, i, `/v1/target-groups/${t}`, {
      method: "PATCH",
      body: {
        name: String(a.get("name") ?? Z(e, ["name"])).trim(),
        description: String(a.get("description") ?? "").trim(),
        expected_behavior_default: String(a.get("expected_behavior_default") ?? "must_block_before_origin"),
        timezone: String(a.get("timezone") ?? "UTC").trim() || "UTC"
      }
    }), "Target group settings saved.");
  }
  async function ae() {
    window.confirm("Archive this target group?") && (await ne(`archive-target-group-${t}`, () => L(r, i, `/v1/target-groups/${t}`, { method: "DELETE" }), "Target group archived."), window.location.hash = "#target-groups");
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "target-group-detail",
        eyebrow: "Declared business service"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "page-head",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("h2", { children: Z(e, ["name", "id"]) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
          g.length,
          " declared targets · ",
          Z(e, ["environment_id"], "tenant scope"),
          " · expected ",
          vn(Z(e, ["expected_behavior_default"], "must_block_before_origin"))
        ] })] }), /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: "#target-groups",
            children: "All groups"
          }), /* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "default",
            href: "#runs",
            children: "Run checks"
          })]
        })]
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid four",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Targets",
            value: g.length,
            sub: "Declared · never auto-discovered",
            icon: ke,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Bound agents",
            value: y.length,
            sub: "Outbound observers for this group",
            icon: re,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Open findings",
            value: x.length,
            sub: "Unresolved gaps on this group",
            icon: Ae,
            tone: x.length > 0 ? "danger" : "muted"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Last run",
            value: S ? Z(S, ["id"]) : "—",
            sub: S ? I(S.updated_at ?? S.created_at) : "No runs yet",
            icon: O,
            tone: "muted"
          })
        ]
      }),
      (f || m || s || o) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: m || s ? "form-banner error" : "form-banner",
        children: m || s || f || "Loading target group detail..."
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: c,
        options: w,
        onChange: l,
        className: "tabs-wrap"
      }),
      c === "overview" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Group summary" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Fields from `/v1/target-groups/",
          "{id}",
          "`."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Group ID" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: /* @__PURE__ */ (0, R.jsx)("code", { children: t }) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environment" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["environment_id"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Default expected behavior" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: vn(Z(e, ["expected_behavior_default"], "must_block_before_origin")) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Timezone" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["timezone"], "UTC") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Created" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(e.created_at) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Description" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["description"], "No description recorded.") })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Validation posture" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Counts derived from tenant list APIs for this group." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Recent runs" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: _.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Bound policies" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: b.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Evidence records" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: n.evidence.filter((e) => Z(e, ["target_group_id"], "") === t).length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Latest run status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: S ? Z(S, ["status"], "pending") : "none" })] })
          ]
        })] })]
      }) : null,
      c === "targets" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Declared targets" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Manual declarations loaded from the target-group detail API." })] }), /* @__PURE__ */ (0, R.jsxs)(z, {
        tone: "success",
        children: [g.length, " targets"]
      })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [/* @__PURE__ */ (0, R.jsx)(J, {
        columns: T,
        items: g,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: ke,
          title: "No targets declared.",
          body: "Add targets from the Target Groups page.",
          actionLabel: "Open Target Groups",
          actionHref: "#target-groups"
        })
      }), /* @__PURE__ */ (0, R.jsx)("div", {
        className: "form-actions",
        children: /* @__PURE__ */ (0, R.jsx)(V, {
          size: "sm",
          variant: "secondary",
          href: "#target-groups",
          children: "Manage targets"
        })
      })] })] }) : null,
      c === "expected-behavior" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [
        /* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Expected behavior" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Customer-declared protection expectations for this group." })] }),
        /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Group default" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: vn(Z(e, ["expected_behavior_default"], "must_block_before_origin")) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Safety policy" }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [
              Fa(e, ["safety_policy", "max_concurrent_runs"], "1"),
              " concurrent runs · ",
              Fa(e, ["safety_policy", "min_seconds_between_runs"], "300"),
              "s cooldown"
            ] })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Per-target overrides" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: g.filter((t) => Z(t, ["expected_behavior"]) !== Z(e, ["expected_behavior_default"], "must_block_before_origin")).length })] })
          ]
        }),
        /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: [{
            key: "value",
            label: "Target",
            render: (e) => Z(e, ["value"])
          }, {
            key: "expected",
            label: "Expected behavior",
            render: (t) => vn(Z(t, ["expected_behavior"], Z(e, ["expected_behavior_default"], "must_block_before_origin")))
          }],
          items: g,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: Ee,
            title: "No target-level behavior yet.",
            body: "Add declared targets to attach expected behavior."
          })
        }) })
      ] }) : null,
      c === "agents" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Bound agents" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Outbound observers scoped to this target group." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: ee,
        items: y,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: re,
          title: "No agents bound.",
          body: "Install an outbound agent and bind it to this declared group.",
          actionLabel: "Open agents",
          actionHref: "#agents"
        })
      }) })] }) : null,
      c === "checks" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Checks on this group" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Safe test policies bound to this declared group." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: te,
        items: b,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: j,
          title: "No policies bound.",
          body: "Bind safe checks through test policies before scheduling runs.",
          actionLabel: "Open test policies",
          actionHref: "#test-policies"
        })
      }) })] }) : null,
      c === "runs" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Recent runs" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Validation runs filtered by `target_group_id`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: E,
        items: _,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: O,
          title: "No runs yet.",
          body: "Start a safe run after declaring targets and binding checks.",
          actionLabel: "Open test runs",
          actionHref: "#runs"
        })
      }) })] }) : null,
      c === "findings" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Findings on this group" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Open and closed gaps tied to this declared scope." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: D,
        items: v,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: Ae,
          title: "No findings recorded.",
          body: "Findings appear after validation runs surface gaps.",
          actionLabel: "Open findings",
          actionHref: "#findings"
        })
      }) })] }) : null,
      c === "settings" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Group settings" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Patch declaration metadata without changing unrelated inventory." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
        className: "product-form",
        onSubmit: ie,
        children: [
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Name" }), /* @__PURE__ */ (0, R.jsx)("input", {
            name: "name",
            defaultValue: Z(e, ["name"])
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Timezone" }), /* @__PURE__ */ (0, R.jsx)("input", {
            name: "timezone",
            defaultValue: Z(e, ["timezone"], "UTC")
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", {
            className: "full",
            children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Description" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
              name: "description",
              rows: 3,
              defaultValue: Z(e, ["description"], "")
            })]
          }),
          /* @__PURE__ */ (0, R.jsxs)("label", {
            className: "full",
            children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Default expected behavior" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "expected_behavior_default",
              defaultValue: Z(e, ["expected_behavior_default"], "must_block_before_origin"),
              children: [
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_block_before_origin",
                  children: "Must be blocked before origin"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_allow_baseline_health",
                  children: "Must allow baseline health"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_challenge_or_rate_limit",
                  children: "Must challenge or rate-limit"
                }),
                /* @__PURE__ */ (0, R.jsx)("option", {
                  value: "must_not_expose_direct_ip",
                  children: "Must not expose direct IP"
                })
              ]
            })]
          }),
          /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "form-actions full",
            children: [
              /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: u !== "",
                children: "Save settings"
              }),
              /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: "#target-groups",
                children: "Manage targets"
              }),
              /* @__PURE__ */ (0, R.jsx)(B, {
                type: "button",
                variant: "danger",
                disabled: u !== "",
                onClick: () => void ae(),
                children: "Archive group"
              })
            ]
          })
        ]
      }, t) })] }) : null
    ]
  });
}
function Ya({ entity: e, entityId: t, data: n, config: r, session: i, onRefresh: a }) {
  let [o, s] = (0, C.useState)("fleet"), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)(""), [m, h] = (0, C.useState)(null), [g, _] = (0, C.useState)([]), [v, y] = (0, C.useState)([]), [b, x] = (0, C.useState)(!1), S = _i("agent-detail").map((e) => ({
    id: e.id,
    label: e.label
  })), w = Z(e, ["target_group_id"], ""), T = Array.isArray(m?.reviews) ? m.reviews.find((e) => Z(e, ["target_group_id"], "") === w) : null, E = pi(n.audit, t), D = mi();
  (0, C.useEffect)(() => {
    if (!["placement", "install"].includes(o)) return;
    let e = !1;
    return x(!0), L(r, i, w ? `/v1/placement/reviews?target_group_id=${encodeURIComponent(w)}` : "/v1/placement/reviews").then((t) => {
      e || h(t);
    }).catch(() => {
      e || h(null);
    }).finally(() => {
      e || x(!1);
    }), () => {
      e = !0;
    };
  }, [
    o,
    r,
    i,
    w
  ]), (0, C.useEffect)(() => {
    if (o !== "upgrades") return;
    let e = !1;
    return x(!0), Promise.all([L(r, i, "/v1/agent-updates"), L(r, i, "/v1/agent-update-trust-keys")]).then(([t, n]) => {
      e || (_(Array.isArray(t.items) ? t.items : []), y(Array.isArray(n.items) ? n.items : []));
    }).catch(() => {
      e || (_([]), y([]));
    }).finally(() => {
      e || x(!1);
    }), () => {
      e = !0;
    };
  }, [
    o,
    r,
    i
  ]);
  async function O() {
    if (!(!t || Z(e, ["status"]) === "revoked")) {
      l(`revoke-${t}`), p(""), d("");
      try {
        await L(r, i, `/v1/agents/${encodeURIComponent(t)}/revoke`, { method: "POST" }), d("Agent revoked."), await a();
      } catch (e) {
        p(e instanceof Error ? e.message : "Agent revoke failed.");
      } finally {
        l("");
      }
    }
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "agent-detail",
        eyebrow: "Outbound observer"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "page-head",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("h2", { children: Z(e, [
          "hostname",
          "name",
          "id"
        ]) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
          /* @__PURE__ */ (0, R.jsx)("code", { children: t }),
          " · ",
          Z(e, ["status"], "unknown"),
          " · ",
          ci(e)
        ] })] }), /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [Z(e, ["status"]) === "revoked" ? null : /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "danger",
            disabled: c !== "",
            onClick: () => void O(),
            children: "Revoke agent"
          }), /* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: "#agents",
            children: "Back to fleet"
          })]
        })]
      }),
      (u || f) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: f ? "form-banner error" : "form-banner",
        children: f || u
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: o,
        options: S,
        onChange: s,
        className: "tabs-wrap"
      }),
      o === "fleet" || o === "overview" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent identity" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Outbound observer metadata from ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents" }),
          "."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Hostname" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["hostname", "name"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Environment" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["environment_id"], "tenant scope") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: w || "unbound" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Health" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ui(e) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Placement" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: li(e) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Last heartbeat" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(e.last_heartbeat_at ?? e.updated_at) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Version" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["version"], "unknown") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Gateway fingerprint" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["fingerprint"], "not registered") })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Actions" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Lifecycle controls for this outbound observer." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "row-actions",
          children: [Z(e, ["status"]) === "revoked" ? null : /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "danger",
            disabled: c !== "",
            onClick: () => void O(),
            children: "Revoke agent"
          }), /* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: "#agents",
            children: "Back to fleet"
          })]
        })] })]
      }) : null,
      o === "install" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Install reference" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Install commands use a fresh bootstrap token from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "#agents" }),
        " or ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "#settings" }),
        "."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)("pre", {
        className: "codeblock",
        children: `curl -fsSL ${D}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${D}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="<BOOTSTRAP_TOKEN>" bash`
      }) })] }) : null,
      o === "health" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Health signals" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Heartbeat freshness derived from agent record timestamps." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Heartbeat freshness" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: di(e) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Last heartbeat" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(e.last_heartbeat_at) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["status"], "unknown") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Version" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["version"], "unknown") })] })
        ]
      })] }) : null,
      o === "placement" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Placement review" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Target-group placement confidence from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/placement/reviews" }),
        "."
      ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          b ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "Loading placement review…"
          }) : null,
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: w || "unbound" })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Placement status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(T, ["status"], "unknown") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Observation mode" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(T, ["observation_mode"], "—") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Summary" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(T, ["summary"], Fa(m, ["summary", "summary"], "Awaiting baseline traffic evidence.")) })] })
        ]
      })] }) : null,
      o === "capabilities" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Capabilities" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Observation modes reported on registration and heartbeat." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Modes" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ci(e) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Placement" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: li(e) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Group placement status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(T, ["status"], "—") })] })
        ]
      })] }) : null,
      o === "logs" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Audit trail" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Metadata-only lifecycle events for this agent from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/audit-log" }),
        "."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: E.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
        icon: se,
        title: "No audit events for this agent yet.",
        body: "Registration, heartbeat, revoke, and update actions appear after lifecycle activity."
      }) : /* @__PURE__ */ (0, R.jsx)("div", {
        className: "kv-list",
        children: E.slice(0, 12).map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Z(e, ["action"]) }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(e.created_at ?? e.timestamp) })] }, Z(e, ["id"], String(t))))
      }) })] }) : null,
      o === "upgrades" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Eligible releases" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Tenant releases from ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agent-updates" }),
          "; agent polls update channel with its credential."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
          b ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "Loading releases…"
          }) : null,
          g.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No published releases for this tenant."
          }) : null,
          /* @__PURE__ */ (0, R.jsx)("div", {
            className: "kv-list",
            children: g.slice(0, 8).map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsxs)("span", { children: [
              Z(e, ["version"]),
              " (",
              Z(e, ["channel"], "stable"),
              ")"
            ] }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["state"], "active") })] }, Z(e, ["id"], "")))
          })
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Trust keys" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Active signing keys from ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agent-update-trust-keys" }),
          "."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [v.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No trust keys registered."
          }) : null, v.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Z(e, ["name"]) }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["status"]) })] }, Z(e, ["id"], "")))]
        })] })]
      }) : null
    ]
  });
}
function Xa({ route: e, data: t, config: n, session: r, onRefresh: i }) {
  let [a, o] = (0, C.useState)("overview"), [s, c] = (0, C.useState)(""), [l, u] = (0, C.useState)(""), [d, f] = (0, C.useState)(""), [p, m] = (0, C.useState)([]), [h, g] = (0, C.useState)([]), [_, v] = (0, C.useState)(null), [y, b] = (0, C.useState)(""), [x, S] = (0, C.useState)(!1), w = (0, C.useMemo)(() => jr({
    "target-group-detail": Z(t.targetGroups[0] ?? null, ["id"], ""),
    "agent-detail": Z(t.agents[0] ?? null, ["id"], ""),
    "run-detail": Z(t.runs[0] ?? null, ["id"], ""),
    "waf-asset-detail": Z(t.wafAssets[0] ?? null, ["id"], ""),
    "cve-detail": Z(t.cvePipeline[0] ?? null, ["id"], ""),
    "supply-chain-detail": Z(t.supplyChainRisks[0] ?? null, ["id"], ""),
    "discovery-entity": Z(t.discoveryEntities[0] ?? t.discoveryCandidates[0] ?? null, ["id", "entity_id"], ""),
    "tenant-detail": Z(t.internalTenants[0] ?? null, ["tenant_id", "id"], "")
  }[e] ?? ""), [e, t]), T = t.targetGroups.find((e) => Z(e, ["id"], "") === w) ?? null, E = t.agents.find((e) => Z(e, ["id"], "") === w) ?? null, D = t.runs.find((e) => Z(e, ["id"], "") === w) ?? null, O = t.wafAssets.find((e) => Z(e, ["id"], "") === w) ?? null, ee = t.discoveryEntities.find((e) => Z(e, ["id", "entity_id"], "") === w) ?? t.discoveryCandidates.find((e) => Z(e, ["id", "entity_id"], "") === w) ?? null, te = t.internalTenants.find((e) => Z(e, ["tenant_id", "id"], "") === w) ?? null, ne = t.cvePipeline.find((e) => Z(e, ["id"], "") === w) ?? null, re = t.supplyChainRisks.find((e) => Z(e, ["id"], "") === w) ?? null, ie = Ua(e === "target-group-detail" && !!w, n, r, `/v1/target-groups/${encodeURIComponent(w)}`, T), ae = Ua(e === "run-detail" && !!w, n, r, `/v1/test-runs/${encodeURIComponent(w)}`, D), oe = Ua(e === "waf-asset-detail" && !!w, n, r, `/v1/waf/assets/${encodeURIComponent(w)}`, O), k = Ua(e === "supply-chain-detail" && !!w, n, r, `/v1/waf/supply-chain/risks/${encodeURIComponent(w)}`, re), A = Wa(e === "cve-detail" && !!w, n, r, "/v1/waf/cve-pipeline", w, ne), se = Ua(e === "tenant-detail" && !!w && r.principal === "staff", n, r, `/internal/admin/tenants/${encodeURIComponent(w)}`, null), ce = e === "target-group-detail" ? ie : e === "run-detail" ? ae : e === "waf-asset-detail" ? oe : e === "supply-chain-detail" ? k : e === "cve-detail" ? A : {
    detail: null,
    error: "",
    loading: !1
  }, j = e === "agent-detail" ? E : e === "discovery-entity" ? ee : e === "tenant-detail" ? te : ce.detail, le = e === "target-group-detail" ? Z(j, ["id"], "") : Z(j, ["target_group_id"], ""), ue = t.runs.filter((e) => Z(e, ["target_group_id"], "") === le), M = t.findings.filter((e) => Z(e, ["target_group_id"], "") === le), de = t.agents.filter((e) => Z(e, ["target_group_id"], "") === le), fe = t.evidence.filter((e) => Z(e, ["test_run_id"], "") === w || Z(e, ["target_group_id"], "") === le), pe = e === "target-group-detail" ? La(j, ["targets"]) : [];
  (0, C.useEffect)(() => {
    if (e !== "cve-detail" || !w) {
      g([]), v(null), b(""), S(!1);
      return;
    }
    let t = !1;
    return S(!0), b(""), Promise.allSettled([L(n, r, `/v1/waf/cve-pipeline/${encodeURIComponent(w)}/playbook`), L(n, r, `/v1/waf/cve-pipeline/${encodeURIComponent(w)}/match`, {
      method: "POST",
      body: {}
    })]).then(([e, n]) => {
      if (t) return;
      let r = [];
      if (e.status === "fulfilled") {
        let t = e.value;
        v(Ra(t, ["playbook"]) ?? t);
      } else {
        v(null);
        let t = e.reason;
        r.push(t instanceof Error ? t.message : "CVE playbook fetch failed.");
      }
      if (n.status === "fulfilled") {
        let e = n.value, t = Array.isArray(e?.matches) ? e.matches : [];
        g(t);
      } else {
        g([]);
        let e = n.reason;
        r.push(e instanceof Error ? e.message : "CVE asset match fetch failed.");
      }
      b(r.join(" "));
    }).finally(() => {
      t || S(!1);
    }), () => {
      t = !0;
    };
  }, [
    e,
    w,
    n,
    r
  ]), (0, C.useEffect)(() => {
    if (e !== "run-detail" || !w) {
      m([]);
      return;
    }
    let t = !1;
    return L(n, r, `/v1/test-runs/${encodeURIComponent(w)}/events`).then((e) => {
      if (t) return;
      let n = Array.isArray(e.items) ? e.items : [];
      m(n);
    }).catch(() => {
      t || m([]);
    }), () => {
      t = !0;
    };
  }, [
    e,
    w,
    n,
    r
  ]);
  async function me(e, t, n) {
    c(e), f(""), u("");
    try {
      await t(), u(n), await i();
    } catch (e) {
      f(e instanceof Error ? e.message : "Action failed.");
    } finally {
      c("");
    }
  }
  let he = (0, C.useMemo)(() => j ? Ba(e, j, { cveMatches: h }) : [], [
    j,
    e,
    h
  ]), ge = he.length > 0 ? "Evidence-backed factors" : "Derived summary", _e = he.length > 0 ? "Scores and signals returned by tenant entity APIs." : "No backend factor payload is available for this entity yet.", ve = he.length > 0 ? "No evidence factors yet." : "No backend factors yet.", ye = he.length > 0 ? "Factors appear after the backend returns entity-specific readiness or posture signals." : "Run the route-specific API actions (triage, validation, posture finalize) to populate factor data.", be = (0, C.useMemo)(() => j ? e === "run-detail" ? [
    {
      label: "Run created",
      at: j.created_at
    },
    {
      label: "Run started",
      at: j.started_at
    },
    {
      label: "Probe window",
      at: j.probe_started_at ?? j.updated_at
    },
    {
      label: "Verdict recorded",
      at: Fa(j, ["verdict", "finalized_at"], "") || j.completed_at
    }
  ].filter((e) => e.at) : [
    {
      label: "Record created",
      at: j.created_at
    },
    {
      label: "Last updated",
      at: j.updated_at
    },
    {
      label: "Latest evidence",
      at: ue[0]?.updated_at ?? ue[0]?.created_at
    },
    {
      label: "Latest finding",
      at: M[0]?.updated_at ?? M[0]?.created_at
    }
  ].filter((e) => e.at) : [], [
    j,
    e,
    M,
    ue
  ]);
  return e === "tenant-detail" ? w ? r.principal === "staff" ? /* @__PURE__ */ (0, R.jsx)(qa, {
    entityId: w,
    detail: se.detail,
    data: t,
    config: n,
    session: r,
    onRefresh: i,
    loading: se.loading,
    loadError: se.error
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: e,
      eyebrow: "Staff tenant operations"
    }), /* @__PURE__ */ (0, R.jsx)(q, {
      icon: je,
      title: "Staff session required.",
      body: "Tenant detail loads internal management APIs after staff authentication.",
      actionLabel: "Open staff login",
      actionHref: "/internal/admin/login"
    })]
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: e,
      eyebrow: "Staff tenant operations"
    }), /* @__PURE__ */ (0, R.jsx)(q, {
      icon: ke,
      title: "No tenant selected.",
      body: "Open a tenant from the staff directory with ?id= or use the Detail link on #admin.",
      actionLabel: "Open staff admin",
      actionHref: "#admin"
    })]
  }) : e === "target-group-detail" ? w ? !j && ce.loading ? /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: e,
      eyebrow: "Declared business service"
    }), /* @__PURE__ */ (0, R.jsx)("div", {
      className: "form-banner",
      children: "Loading target group detail..."
    })]
  }) : j ? /* @__PURE__ */ (0, R.jsx)(Ja, {
    entity: j,
    entityId: w,
    data: t,
    config: n,
    session: r,
    onRefresh: i,
    loading: ce.loading,
    loadError: ce.error
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: e,
      eyebrow: "Declared business service"
    }), /* @__PURE__ */ (0, R.jsx)(q, {
      icon: ke,
      title: "Target group not found.",
      body: ce.error || "The requested group is missing, archived, or outside this tenant scope.",
      actionLabel: "Open target groups",
      actionHref: "#target-groups"
    })]
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: e,
      eyebrow: "Declared business service"
    }), /* @__PURE__ */ (0, R.jsx)(q, {
      icon: ke,
      title: "No target group selected.",
      body: "Open a group from the list with ?id= or use the Detail link on #target-groups.",
      actionLabel: "Open target groups",
      actionHref: "#target-groups"
    })]
  }) : !w || !j ? /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: e,
      eyebrow: "Detail surface"
    }), /* @__PURE__ */ (0, R.jsx)(q, {
      icon: ke,
      title: "No entity selected.",
      body: "Open a list row with ?id= or seed workspace data so this detail route can resolve a record."
    })]
  }) : e === "run-detail" ? /* @__PURE__ */ (0, R.jsx)(Ga, {
    entity: j,
    entityId: w,
    data: t,
    config: n,
    session: r,
    onRefresh: i,
    runEvents: p,
    loading: ce.loading,
    loadError: ce.error
  }) : e === "agent-detail" ? /* @__PURE__ */ (0, R.jsx)(Ya, {
    entity: j,
    entityId: w,
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: e,
        eyebrow: "Entity detail"
      }),
      (l || d || ce.error || y || ce.loading || x) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: d || ce.error || y ? "form-banner error" : "form-banner",
        children: d || ce.error || y || l || (x ? "Loading CVE playbook and matches..." : "Loading entity detail...")
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: a,
        options: [
          {
            id: "overview",
            label: "Overview"
          },
          {
            id: "timeline",
            label: "Timeline"
          },
          {
            id: "related",
            label: "Related evidence"
          },
          {
            id: "actions",
            label: "Actions"
          }
        ],
        onChange: o,
        className: "tabs-wrap"
      }),
      a === "overview" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "detail-layout",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: Z(j, [
          "name",
          "hostname",
          "canonical_url",
          "cve_id",
          "organization_name",
          "id"
        ], Wn.get(e)?.label) }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          /* @__PURE__ */ (0, R.jsx)("code", { children: w }),
          " · ",
          he.length > 0 ? "evidence-backed detail from tenant APIs" : "entity detail with list fallback until API factors are available"
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Route" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Wn.get(e)?.label })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, [
              "status",
              "state",
              "lifecycle_state",
              "stage"
            ], "recorded") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Updated" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(j.updated_at ?? j.created_at) })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, {
          className: "detail-primary",
          children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: ge }), /* @__PURE__ */ (0, R.jsx)(G, { children: _e })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(Va, {
            factors: he,
            emptyTitle: ve,
            emptyBody: ye
          }) })]
        })]
      }) : null,
      a === "timeline" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Timeline" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Recorded milestones for this entity." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(Ha, { items: be }) })] }) : null,
      a === "related" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Related evidence" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Live counts and links from the current workspace payload." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Runs" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ue.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Findings" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: M.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Agents" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: de.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Evidence" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: fe.length })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Targets" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: pe.length })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Linked records" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Open related runs, findings, and agents." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "row-actions",
          children: [
            ue.slice(0, 4).map((e) => /* @__PURE__ */ (0, R.jsxs)(V, {
              size: "sm",
              variant: "secondary",
              href: Mr("run-detail", Z(e, ["id"], "")),
              children: ["Run ", Z(e, ["id"], "")]
            }, Z(e, ["id"], ""))),
            de.slice(0, 3).map((e) => /* @__PURE__ */ (0, R.jsxs)(V, {
              size: "sm",
              variant: "ghost",
              href: Mr("agent-detail", Z(e, ["id"], "")),
              children: ["Agent ", Z(e, ["hostname", "id"], "")]
            }, Z(e, ["id"], ""))),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#findings",
              children: "Open findings"
            }),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#evidence",
              children: "Open evidence"
            })
          ]
        })] })]
      }) : null,
      a === "actions" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Entity actions" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Route-specific mutations backed by tenant APIs." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "row-actions",
        children: [
          e === "waf-asset-detail" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: s !== "",
              onClick: () => void me(`waf-validate-${w}`, () => L(n, r, "/v1/waf/validations", {
                method: "POST",
                body: {
                  waf_asset_id: w,
                  modes: ["marker"]
                }
              }), "Safe WAF validation started."),
              children: "Run validation"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "ghost",
              disabled: s !== "",
              onClick: () => void me(`waf-exception-${w}`, () => L(n, r, `/v1/waf/assets/${encodeURIComponent(w)}/exception`, {
                method: "POST",
                body: {
                  owner: "edge-team",
                  reason: "approved_scope_exception",
                  expires_at: new Date(Date.now() + 2160 * 60 * 60 * 1e3).toISOString()
                }
              }), "WAF exception recorded."),
              children: "Create exception"
            }),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#waf-posture",
              children: "Open WAF posture"
            })
          ] }) : null,
          e === "cve-detail" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: s !== "",
              onClick: () => void me(`cve-triage-${w}`, () => L(n, r, `/v1/waf/cve-pipeline/${encodeURIComponent(w)}/triage`, {
                method: "POST",
                body: {}
              }), "CVE item triaged."),
              children: "Run triage"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "ghost",
              disabled: s !== "",
              onClick: () => void me(`cve-validate-${w}`, () => L(n, r, `/v1/waf/cve-pipeline/${encodeURIComponent(w)}/validate`, { method: "POST" }), "Safe validation delegated."),
              children: "Validate exposure"
            }),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#cve-pipeline",
              children: "Open CVE pipeline"
            })
          ] }) : null,
          e === "supply-chain-detail" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: s !== "",
              onClick: () => void me(`supply-state-${w}`, () => L(n, r, `/v1/waf/supply-chain/risks/${encodeURIComponent(w)}/state`, {
                method: "PATCH",
                body: { state: "confirmed" }
              }), "Risk state updated."),
              children: "Confirm risk"
            }),
            /* @__PURE__ */ (0, R.jsxs)("form", {
              className: "product-form compact",
              onSubmit: (e) => {
                e.preventDefault();
                let t = new FormData(e.currentTarget), i = String(t.get("target_phase") ?? "AP2_manual_custody").trim();
                me(`supply-phase-${w}`, () => L(n, r, `/v1/waf/supply-chain/risks/${encodeURIComponent(w)}/phase-authorization`, {
                  method: "POST",
                  body: {
                    target_phase: i,
                    customer_approval_reference: String(t.get("customer_approval_reference") ?? "").trim(),
                    customer_signed_at: (/* @__PURE__ */ new Date()).toISOString(),
                    custody_ids: [String(t.get("custody_id") ?? `custody_${w}`).trim()],
                    manual_workflow_owner: String(t.get("manual_workflow_owner") ?? "supply-chain-owner").trim()
                  }
                }), "Phase authorization recorded.");
              },
              children: [
                /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target phase" }), /* @__PURE__ */ (0, R.jsxs)("select", {
                  name: "target_phase",
                  defaultValue: "AP2_manual_custody",
                  children: [/* @__PURE__ */ (0, R.jsx)("option", {
                    value: "AP2_manual_custody",
                    children: "AP2 manual custody"
                  }), /* @__PURE__ */ (0, R.jsx)("option", {
                    value: "AP3_governed_active",
                    children: "AP3 governed active"
                  })]
                })] }),
                /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Approval reference" }), /* @__PURE__ */ (0, R.jsx)("input", {
                  name: "customer_approval_reference",
                  placeholder: "ticket-123",
                  required: !0
                })] }),
                /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Custody ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
                  name: "custody_id",
                  placeholder: `custody_${w}`,
                  required: !0
                })] }),
                /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Workflow owner" }), /* @__PURE__ */ (0, R.jsx)("input", {
                  name: "manual_workflow_owner",
                  defaultValue: "supply-chain-owner",
                  required: !0
                })] }),
                /* @__PURE__ */ (0, R.jsx)("div", {
                  className: "form-actions",
                  children: /* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    type: "submit",
                    disabled: s !== "",
                    children: "Authorize phase"
                  })
                })
              ]
            }),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#supply-chain",
              children: "Open supply chain"
            })
          ] }) : null,
          e === "discovery-entity" ? /* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: "#discovery",
            children: "Open discovery"
          }) : null
        ]
      })] }) : null,
      a === "overview" && e === "waf-asset-detail" && /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "WAF effectiveness" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Asset posture from `/v1/waf/assets/:id`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Vendor" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["detected_vendor", "expected_vendor_hint"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Criticality" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["business_criticality", "criticality"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Control bypass" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Fa(j, ["effectiveness", "control_bypass_status"], Z(j, ["control_bypass_status"], "unknown")) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Pass rate" }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [Math.round(Ia(j, ["effectiveness", "scenario_pass_rate"], Ia(j, ["scenario_pass_rate"], 0))), "%"] })] })
        ]
      })] }),
      a === "overview" && e === "cve-detail" && /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "CVE detail" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Metadata-only triage and mitigation workflow for one pipeline item." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "CVE ID" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["cve_id", "id"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Severity" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["severity"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Stage" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["stage"], "ingest") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Known exploited" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: j?.known_exploited === !0 ? "yes" : "no" })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Triage summary" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Fa(j, ["triage_result", "summary"], "Run triage to populate factors.") })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Asset matches" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Declared asset correlation from `/v1/waf/cve-pipeline/:id/match`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
          x ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "Loading asset matches…"
          }) : null,
          !x && h.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No asset matches yet. Run triage and match from the actions tab."
          }) : null,
          h.length > 0 ? /* @__PURE__ */ (0, R.jsx)("div", {
            className: "kv-list",
            children: h.slice(0, 6).map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Z(e, ["asset_display", "asset_id"], `match-${t + 1}`) }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["match_source"], "declared") })] }, Z(e, ["asset_id", "waf_asset_id"], String(t))))
          }) : null
        ] })] })]
      }), _ ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Mitigation playbook" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Grouped vendor slices from `/v1/waf/cve-pipeline/:id/playbook`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(_, ["status"], "draft") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "CVE" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(_, ["cve_id"], Z(j, ["cve_id"])) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Vendor slices" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: La(_, ["vendor_slices"]).length })] }),
          La(_, ["vendor_slices"]).slice(0, 4).map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Z(e, ["vendor"], `vendor-${t + 1}`) }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(e, ["status"], "draft") })] }, Z(e, ["vendor"], String(t))))
        ]
      })] }) : null] }),
      a === "overview" && e === "supply-chain-detail" && /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Supply chain risk detail" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Evidence summary and remediation steps from `/v1/waf/supply-chain/risks/:id`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Hostname" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["hostname", "id"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Exposure type" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["exposure_type"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Severity" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["severity"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "State" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["state"], "suspected") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Confidence" }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [Math.round(Ia(j, ["confidence"], 0) * 100), "%"] })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Remediation steps" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: La(j, ["remediation_steps"]).map((e) => typeof e == "string" ? e : Z(e, ["step", "description"])).join(" · ") || "No steps recorded." })] })
        ]
      })] }),
      a === "overview" && e === "discovery-entity" && /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Discovery decision trail" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Approval-gated candidate metadata only." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Entity type" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, [
            "entity_type",
            "candidate_type",
            "type"
          ]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Confidence" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["confidence", "confidence_score"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "State" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["state"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Source" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(j, ["source_type", "source_summary"], "declared") })] })
        ]
      })] })
    ]
  });
}
function Za({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(null), [f, p] = (0, C.useState)(!1), m = (0, C.useRef)(!1), h = (0, C.useMemo)(() => jr(Z(e.reports[0] ?? null, ["id"], "")), [e.reports]), g = e.reports.find((e) => Z(e, ["id"], "") === h) ?? null, _ = Ua(!!h, t, n, `/v1/reports/${encodeURIComponent(h)}`, g), v = _.detail;
  (0, C.useEffect)(() => {
    m.current = !1;
  }, [h]), (0, C.useEffect)(() => {
    if (!h || !v) {
      d(null), p(!1);
      return;
    }
    if (m.current) return;
    let e = !1;
    p(!0), l("");
    async function r() {
      try {
        let r = Nn(t, n), i = await fetch(`/v1/reports/${encodeURIComponent(h)}/export?format=json`, { headers: r });
        if (!i.ok) {
          let e = await i.json().catch(() => null);
          throw Error(String(e?.message ?? e?.error ?? `Export returned ${i.status}`));
        }
        let a = await i.json(), o = Ra(a, ["custody"]), s = Ra(a, ["payload"]), c = null;
        if (o && s) {
          let e = await L(t, n, "/v1/custody/verify", {
            method: "POST",
            body: {
              payload: s,
              custody: o
            }
          });
          c = Ra(e, ["verification"]) ?? e;
        }
        e || d({
          reportId: h,
          format: "json",
          title: Fa(s, ["title"], Z(v, ["title", "id"], h)),
          contentSha256: Z(o ?? {}, ["content_sha256"], ""),
          artifactId: Z(o ?? {}, ["artifact_id"], ""),
          schemaVersion: Z(o ?? {}, ["schema_version"], ""),
          verification: c
        });
      } catch (t) {
        e || (d(null), l(t instanceof Error ? t.message : "Could not load custody preview."));
      } finally {
        e || p(!1);
      }
    }
    return r(), () => {
      e = !0;
    };
  }, [
    h,
    v,
    t,
    n
  ]);
  async function y(e, t, n) {
    a(e), l(""), s("");
    try {
      let e = await t();
      return s(n), e;
    } catch (e) {
      let t = e.payload;
      return l(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Report action failed.")), null;
    } finally {
      a("");
    }
  }
  async function b(e, i) {
    e && await y(`export-${e}-${i}`, async () => {
      let a = Nn(t, n), o = await fetch(`/v1/reports/${encodeURIComponent(e)}/export?format=${i}`, { headers: a }), s = o.headers.get("content-type") ?? "";
      if (!o.ok) {
        let e = await o.json().catch(() => null);
        throw Error(String(e?.message ?? e?.error ?? `Export returned ${o.status}`));
      }
      if (i === "json" || s.includes("application/json")) {
        let a = await o.json(), s = Ra(a, ["custody"]), c = Ra(a, ["payload"]), l = null;
        if (s && c) {
          let e = await L(t, n, "/v1/custody/verify", {
            method: "POST",
            body: {
              payload: c,
              custody: s
            }
          });
          l = Ra(e, ["verification"]) ?? e;
        }
        return m.current = !0, d({
          reportId: e,
          format: i,
          title: Fa(c, ["title"], Z(v, ["title", "id"], e)),
          contentSha256: Z(s ?? {}, ["content_sha256"], ""),
          artifactId: Z(s ?? {}, ["artifact_id"], ""),
          schemaVersion: Z(s ?? {}, ["schema_version"], ""),
          verification: l
        }), await r(), a;
      }
      let c = await o.text();
      return m.current = !0, d({
        reportId: e,
        format: i,
        title: Z(v, ["title", "id"], e),
        textPreview: c.slice(0, 900)
      }), await r(), c;
    }, `Report exported as ${i}.`);
  }
  if (!h || !v) return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, {
      route: "report-detail",
      eyebrow: "Report detail"
    }), /* @__PURE__ */ (0, R.jsx)(q, {
      icon: le,
      title: "No report selected.",
      body: "Open a report from the Reports list with ?id= or generate a report first.",
      actionLabel: "Open Reports",
      actionHref: "#reports"
    })]
  });
  let x = u?.verification ? Z(u.verification, ["ok"], "") : "", S = Ia(v, ["summary", "readiness_score"], 0), w = Ia(v, ["summary", "open_findings"], 0);
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: "report-detail",
        eyebrow: "Report detail"
      }),
      (o || c || _.error || _.loading || f) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c || _.error ? "form-banner error" : "form-banner",
        children: c || _.error || o || (_.loading ? "Loading report detail..." : "Loading custody preview...")
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "detail-layout",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: Z(v, ["title", "id"], "Report") }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [/* @__PURE__ */ (0, R.jsx)("code", { children: h }), " · resolved from `/v1/reports` and `/v1/reports/:id`"] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Kind" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(v, ["kind"]) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Created" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(v.created_at) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Z(v, ["status"], "ready") })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Readiness" }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [S, "%"] })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Open findings" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: w })] })
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, {
          className: "detail-primary",
          children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Custody preview" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "JSON export digest metadata verified through `/v1/custody/verify`." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
            className: u?.contentSha256 || u?.textPreview ? "kv-list" : "",
            children: !u && !f ? /* @__PURE__ */ (0, R.jsx)(q, {
              icon: j,
              title: "Custody preview unavailable.",
              body: "Export JSON to inspect custody metadata for this report."
            }) : u?.contentSha256 ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Artifact" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.artifactId })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "content_sha256" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.contentSha256 })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Schema" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: u.schemaVersion })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Verification" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: x || "verified" })] })
            ] }) : u?.textPreview ? /* @__PURE__ */ (0, R.jsx)("pre", {
              className: "codeblock",
              children: u.textPreview
            }) : /* @__PURE__ */ (0, R.jsx)("p", {
              className: "muted",
              children: "Loading custody preview..."
            })
          })]
        })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Export formats" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Exports call `/v1/reports/:id/export`; JSON exports include custody manifests for verification." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "stack-tight",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void b(h, "json"),
              children: "Export JSON"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void b(h, "markdown"),
              children: "Export Markdown"
            }),
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: i !== "",
              onClick: () => void b(h, "html"),
              children: "Export HTML"
            }),
            /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#reports",
              children: "Back to reports"
            })
          ]
        }), /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: "PDF export is not available in this slice; backend report exports support JSON, Markdown, and HTML only."
        })]
      })] })
    ]
  });
}
//#endregion
//#region apps/web/react/src/components/findings/finding-explanation-panel.tsx
function Qa(e, t, n = "") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function $a(e, t) {
  if (!e || !t) return null;
  let n = { ...t }, r = Qa(e, ["remediation_template"], "");
  return r && (n.remediation_template = r), n;
}
function eo({ finding: e, config: t, session: n }) {
  let [r, i] = (0, C.useState)(null), [a, o] = (0, C.useState)([]), [s, c] = (0, C.useState)(!1), l = Qa(e, ["test_run_id"], "");
  (0, C.useEffect)(() => {
    if (!l) {
      i(null), o([]), c(!1);
      return;
    }
    let e = !1;
    return c(!0), Promise.all([L(t, n, `/v1/test-runs/${l}`), L(t, n, `/v1/test-runs/${l}/events`)]).then(([t, n]) => {
      if (e) return;
      i(t);
      let r = Array.isArray(n.items) ? n.items : [];
      o(r);
    }).catch(() => {
      e || (i(null), o([]));
    }).finally(() => {
      e || c(!1);
    }), () => {
      e = !0;
    };
  }, [
    l,
    t,
    n
  ]);
  let u = (0, C.useMemo)(() => $a(e, r), [e, r]);
  return e ? l ? s && !u ? /* @__PURE__ */ (0, R.jsx)("p", {
    className: "muted",
    children: "Loading linked run evidence for this finding..."
  }) : /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "finding-explanation-panel",
    children: [/* @__PURE__ */ (0, R.jsxs)("p", {
      className: "muted",
      children: [
        "Run ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: l }),
        r ? ` · Check ${Qa(r, ["check_id"], "—")}` : ""
      ]
    }), /* @__PURE__ */ (0, R.jsx)(Jr, {
      detail: u,
      events: a,
      heading: "Why this finding?"
    })]
  }) : /* @__PURE__ */ (0, R.jsxs)("section", {
    className: "verdict-explanation verdict-explanation--pending",
    children: [
      /* @__PURE__ */ (0, R.jsx)("h4", { children: "Why this finding?" }),
      /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted",
        children: "This finding has no linked test run; probe and agent evidence cannot be loaded."
      }),
      Qa(e, ["notes"], "") ? /* @__PURE__ */ (0, R.jsx)("div", {
        className: "verdict-explanation-grid",
        children: /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "verdict-explanation-item",
          children: [/* @__PURE__ */ (0, R.jsx)("span", {
            className: "verdict-explanation-label",
            children: "Conclusion"
          }), /* @__PURE__ */ (0, R.jsx)("span", {
            className: "verdict-explanation-value",
            children: Qa(e, ["notes"])
          })]
        })
      }) : null,
      Qa(e, ["remediation_template"], "") ? /* @__PURE__ */ (0, R.jsx)("div", {
        className: "verdict-explanation-grid",
        children: /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "verdict-explanation-item",
          children: [/* @__PURE__ */ (0, R.jsx)("span", {
            className: "verdict-explanation-label",
            children: "Remediation"
          }), /* @__PURE__ */ (0, R.jsx)("span", {
            className: "verdict-explanation-value",
            children: Qa(e, ["remediation_template"])
          })]
        })
      }) : null
    ]
  }) : /* @__PURE__ */ (0, R.jsx)("p", {
    className: "muted",
    children: "Select a finding to review evidence-backed explanation."
  });
}
//#endregion
//#region apps/web/react/src/lib/custody.ts
var to = "astranull.custody.v1", no = "json-key-sorted-v1";
function ro(e) {
  if (e == null) return null;
  if (Array.isArray(e)) return e.map((e) => ro(e));
  if (typeof e != "object") return e;
  let t = e, n = {};
  for (let e of Object.keys(t).sort()) t[e] !== void 0 && (n[e] = ro(t[e]));
  return n;
}
function io(e) {
  if (e === null) return "null";
  let t = typeof e;
  if (t === "string" || t === "boolean" || t === "number") return JSON.stringify(e);
  if (Array.isArray(e)) return `[${e.map((e) => io(e)).join(",")}]`;
  let n = e;
  return `{${Object.keys(n).sort().map((e) => `${JSON.stringify(e)}:${io(n[e])}`).join(",")}}`;
}
function ao(e) {
  return io(ro(e));
}
async function oo(e) {
  if (!globalThis.crypto?.subtle) throw Error("custody_digest_unavailable");
  let t = new TextEncoder().encode(e), n = await globalThis.crypto.subtle.digest("SHA-256", t);
  return [...new Uint8Array(n)].map((e) => e.toString(16).padStart(2, "0")).join("");
}
async function so(e) {
  return oo(ao(e));
}
async function co(e, t) {
  return {
    schema_version: to,
    artifact_type: "evidence_chain_export",
    format: "json",
    content_sha256: await so(e),
    content_canonicalization: no,
    created_at: String(e.exported_at ?? (/* @__PURE__ */ new Date()).toISOString()),
    created_by: "react_portal_export",
    tenant_id: t ?? null,
    subject_ids: [...new Set((Array.isArray(e.evidence_ids) ? e.evidence_ids : []).filter(Boolean))].sort()
  };
}
//#endregion
//#region apps/web/react/src/lib/evidence-export.ts
function lo(e, t) {
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return "";
}
function uo(e) {
  let t = e.evidence ?? [], n = e.runs ?? [], r = e.verdicts ?? [], i = e.findings ?? [], a = Object.fromEntries(n.map((e) => [lo(e, ["id"]), e])), o = t.map((e) => {
    let t = lo(e, ["test_run_id"]), n = t ? a[t] : null, o = r.find((e) => lo(e, ["test_run_id"]) === t) ?? r.find((t) => (Array.isArray(t.evidence_ids) ? t.evidence_ids : []).includes(lo(e, ["id"]))), s = i.filter((t) => (Array.isArray(t.evidence_ids) ? t.evidence_ids : []).includes(lo(e, ["id"])));
    return {
      evidence_id: lo(e, ["id"]),
      label: lo(e, ["label"]),
      test_run_id: t || null,
      run_status: n ? lo(n, ["status"]) : null,
      verdict: o ? lo(o, ["verdict"]) : null,
      verdict_confidence: o?.confidence ?? null,
      finding_ids: s.map((e) => lo(e, ["id"])),
      created_at: e.created_at ?? null
    };
  }), s = [];
  for (let e of r) {
    let n = Array.isArray(e.evidence_ids) ? e.evidence_ids : [];
    for (let r of n) t.some((e) => lo(e, ["id"]) === r) || s.push({
      evidence_id: r,
      test_run_id: lo(e, ["test_run_id"]),
      verdict: lo(e, ["verdict"]),
      source: "verdict_reference"
    });
  }
  let c = {
    exported_at: (/* @__PURE__ */ new Date()).toISOString(),
    evidence_ids: t.map((e) => lo(e, ["id"])).filter(Boolean),
    chain: o,
    orphan_references: s
  };
  return {
    payload: c,
    json: JSON.stringify(c, null, 2),
    idList: c.evidence_ids.join("\n")
  };
}
function fo(e) {
  return [
    ["Evidence IDs", String(e.payload.evidence_ids.length)],
    ["Chain links", String(e.payload.chain.length)],
    ["Orphan references", String(e.payload.orphan_references.length)],
    ["Exported at", e.payload.exported_at]
  ];
}
//#endregion
//#region apps/web/react/src/lib/findings-helpers.ts
var po = {
  critical: 24,
  high: 48,
  medium: 72,
  low: 168
}, mo = {
  origin: "Origin",
  path: "Path",
  l3_l4: "L3/L4",
  dns: "DNS",
  l7: "L7/API",
  waf: "WAF",
  tls: "TLS",
  protocol: "Protocol",
  operations: "Operations",
  high_scale: "High-scale"
};
function ho(e, t, n = "") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function go(e) {
  return mo[e] ?? e.replace(/_/g, " ");
}
function _o(e) {
  if (!e) return null;
  let t = Date.parse(String(e));
  return Number.isFinite(t) ? t : null;
}
function vo(e) {
  return po[e.toLowerCase()] ?? 168;
}
function yo(e) {
  return ho(e, ["status"]) === "open";
}
function bo(e) {
  let t = _o(e.created_at);
  return t === null ? null : t + vo(ho(e, ["severity"], "low")) * 60 * 60 * 1e3;
}
function xo(e, t = Date.now()) {
  if (!yo(e)) return !1;
  let n = bo(e);
  return n !== null && t > n;
}
function So(e, t = Date.now()) {
  if (ho(e, ["status"]) !== "closed") return !1;
  let n = _o(e.updated_at ?? e.created_at);
  return n === null ? !1 : t - n <= 720 * 60 * 60 * 1e3;
}
function Co(e, t) {
  let n = ho(e, ["vector_family"], "");
  if (n) return n;
  let r = ho(e, ["check_id"], "");
  return ho(t.find((e) => ho(e, ["check_id"]) === r) ?? {}, ["vector_family"], "other");
}
function wo(e, t = Date.now()) {
  let n = e.filter(yo), r = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  n.forEach((e) => {
    let t = ho(e, ["severity"], "low").toLowerCase();
    t in r ? r[t] += 1 : r.low += 1;
  });
  let i = [
    "critical",
    "high",
    "medium",
    "low"
  ].filter((e) => r[e] > 0).map((e) => `${r[e]} ${e}`).join(", ");
  return {
    openCount: n.length,
    openSeverityBreakdown: i || "No open severities",
    acceptedRiskCount: e.filter((e) => ho(e, ["status"]) === "accepted_risk").length,
    closed30dCount: e.filter((e) => So(e, t)).length,
    slaBreachCount: e.filter((e) => xo(e, t)).length
  };
}
function To(e, t, n, r = Date.now()) {
  switch (t) {
    case "open": return e.filter(yo);
    case "accepted-risk": return e.filter((e) => ho(e, ["status"]) === "accepted_risk");
    case "closed": return e.filter((e) => ho(e, ["status"]) === "closed");
    case "sla": return e.filter((e) => xo(e, r));
    case "target-group":
    case "vector": return e.filter(yo);
    default: return e;
  }
}
function Eo(e, t) {
  let n = /* @__PURE__ */ new Map();
  return e.forEach((e) => {
    let t = ho(e, ["target_group_id"], "ungrouped"), r = n.get(t) ?? [];
    r.push(e), n.set(t, r);
  }), [...n.entries()].map(([e, n]) => ({
    groupId: e,
    label: ho(t.find((t) => ho(t, ["id"]) === e) ?? null, [
      "name",
      "display_name",
      "id"
    ], e === "ungrouped" ? "Unassigned target group" : e),
    items: n
  }));
}
function Do(e, t) {
  let n = /* @__PURE__ */ new Map();
  return e.forEach((e) => {
    let r = Co(e, t), i = n.get(r) ?? [];
    i.push(e), n.set(r, i);
  }), [...n.entries()].map(([e, t]) => ({
    family: e,
    label: go(e),
    items: t
  }));
}
function Oo(e) {
  let t = ho(e, ["check_id"], "");
  if (t.startsWith("waf.posture.")) {
    let n = ho(e, ["waf_asset_id"], "") || t.slice(12);
    return n ? {
      kind: "waf-validation",
      wafAssetId: n
    } : null;
  }
  let n = ho(e, ["cve_pipeline_item_id", "cve_item_id"], "");
  if (t.startsWith("cve.") || n) {
    let e = n || (t.startsWith("cve.pipeline.") ? t.slice(13) : "");
    return e ? {
      kind: "cve-retest",
      pipelineId: e
    } : null;
  }
  let r = ho(e, ["retest_url"], "");
  return r.includes("/v1/waf/cve-pipeline/") && (r.includes("/retest") || r.includes("/coordinated-retest")) ? {
    kind: "cve-retest-url",
    retestUrl: r
  } : t ? {
    kind: "safe-run",
    checkId: t
  } : null;
}
//#endregion
//#region apps/web/react/src/lib/checks-helpers.ts
var ko = [
  {
    id: "all",
    label: "All"
  },
  {
    id: "safe",
    label: "Safe"
  },
  {
    id: "soc",
    label: "SOC"
  }
], Ao = /* @__PURE__ */ new Set([
  "origin",
  "path",
  "l7",
  "dns",
  "l3_l4"
]);
function jo(e, t, n = "") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Mo(e, t, n = "") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
function No(e) {
  let t = jo(e, ["safety_class"], "");
  return t === "soc_gated" || t === "soc_only";
}
function Po(e) {
  return jo(e, ["safety_class"]) === "safe";
}
function Fo(e, t) {
  return t === "safe" ? e.filter((e) => Po(e)) : t === "soc" ? e.filter((e) => No(e)) : e;
}
function Io(e) {
  let t = jo(e, ["vector_family"]);
  if (t === "origin") return !0;
  let n = jo(e, ["check_id"]);
  if (n.includes("origin_bypass") || n.includes("host_sni_bypass")) return !0;
  let r = Mo(e, ["probe_profile", "scenario_family"]);
  return t === "waf" && r === "origin_bypass";
}
function Lo(e) {
  let t = jo(e, ["vector_family"]);
  return t === "l7" || t === "waf";
}
function Ro(e, t) {
  if (t === "custom") return [];
  if (t === "recommended") {
    let t = e.filter((e) => Po(e)), n = t.filter((e) => Ao.has(jo(e, ["vector_family"])));
    return (n.length ? n : t).slice(0, 20);
  }
  return t === "origin-bypass" ? e.filter((e) => Io(e)) : t === "l3l4" ? e.filter((e) => jo(e, ["vector_family"]) === "l3_l4") : t === "dns" ? e.filter((e) => jo(e, ["vector_family"]) === "dns") : t === "l7api" ? e.filter((e) => Lo(e)) : t === "protocols" ? e.filter((e) => ["protocol", "tls"].includes(jo(e, ["vector_family"]))) : t === "high-scale" ? e.filter((e) => No(e)) : e;
}
function zo(e, t, n = "all") {
  return Ro(Fo(e, n), t);
}
function Bo(e) {
  let t = e.filter((e) => Po(e)).length, n = e.filter((e) => No(e)).length;
  return {
    all: e.length,
    safe: t,
    soc: n
  };
}
//#endregion
//#region apps/web/react/src/lib/waf-helpers.ts
var Vo = [
  {
    id: "overview",
    label: "Overview"
  },
  {
    id: "roadmap",
    label: "Roadmap"
  },
  {
    id: "assets",
    label: "Assets"
  }
], Ho = [
  "open",
  "acknowledged",
  "remediation_started",
  "retest_pending",
  "resolved",
  "accepted_risk",
  "false_positive"
], Uo = [
  "marker",
  "fingerprint",
  "origin_bypass"
];
function Wo(e = [], t) {
  return t ? e.filter((e) => e.drift_event_id === t).sort((e, t) => String(t.updated_at ?? t.created_at ?? "").localeCompare(String(e.updated_at ?? e.created_at ?? "")))[0] ?? null : null;
}
var Go = {
  tier_1: {
    label: "Tier 1",
    window: "0–14 days"
  },
  tier_2: {
    label: "Tier 2",
    window: "15–60 days"
  },
  tier_3: {
    label: "Tier 3",
    window: "61–180 days"
  },
  tier_4: {
    label: "Tier 4",
    window: "Quarterly review"
  }
};
function Ko(e, t = [], n = 30) {
  if (!e || t.length === 0) return null;
  let r = /* @__PURE__ */ new Date();
  r.setUTCDate(r.getUTCDate() - Math.max(1, n));
  let i = r.toISOString(), a = t.filter((t) => (t.summary_json, t.waf_asset_id === e && t.status === "finalized" && String(t.finalized_at ?? t.created_at ?? "") >= i));
  if (a.length === 0) return null;
  let o = a.filter((e) => e.summary_json?.validation_passed === !0).length;
  return Math.round(o / a.length * 1e4) / 100;
}
function qo(e, t = 30) {
  return e == null || !Number.isFinite(Number(e)) ? "—" : `${Math.round(Number(e) * 100) / 100}% (${t}d)`;
}
function Jo(e) {
  if (!e || typeof e != "object") return "—";
  let t = e.rule_count;
  if (!Number.isFinite(Number(t))) return "—";
  let n = Math.floor(Number(t)), r = e.last_rule_update_at ? I(e.last_rule_update_at) : null;
  return r ? `${n} rules · updated ${r}` : `${n} rules`;
}
function Yo() {
  return [
    "tier_1",
    "tier_2",
    "tier_3",
    "tier_4"
  ];
}
function Xo(e) {
  return Go[e] ?? {
    label: e,
    window: ""
  };
}
function Zo(e = {}) {
  return Yo().reduce((t, n) => t + (e[n]?.length ?? 0), 0);
}
//#endregion
//#region apps/web/react/src/pages/functional-surfaces.tsx
function Q(e, t, n = "—") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function Qo(e, t, n = "—") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
var $o = {
  origin: "Origin",
  path: "Path",
  l3_l4: "L3/L4",
  dns: "DNS",
  l7: "L7/API",
  waf: "WAF",
  tls: "TLS",
  protocol: "Protocol",
  operations: "Operations",
  high_scale: "High-scale"
};
function es(e) {
  return $o[e] ?? e.replace(/_/g, " ");
}
function ts(e, t, n = 0) {
  for (let n of t) {
    let t = e[n];
    if (typeof t == "number" && Number.isFinite(t)) return t;
  }
  return n;
}
function ns(e, t) {
  let n = e;
  for (let e of t) {
    if (!n || typeof n != "object" || Array.isArray(n)) return null;
    n = n[e];
  }
  return n && typeof n == "object" && !Array.isArray(n) ? n : null;
}
function rs(e, t, n = 0) {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return typeof r == "number" && Number.isFinite(r) ? r : n;
}
function is(e, t) {
  return e.deploymentFeatures?.[t] === !0;
}
var as = [
  "open",
  "ticketed",
  "remediation_started",
  "retest_pending",
  "resolved",
  "accepted_risk"
], os = /* @__PURE__ */ new Set(["resolved", "accepted_risk"]), ss = [
  "webhook",
  "jira",
  "servicenow",
  "slack",
  "siem"
];
async function cs(e, t, n, r, i, a, o) {
  e(r), t(""), n("");
  try {
    let e = await i();
    return n(a), o && await o(), e;
  } catch (e) {
    let n = e.payload;
    return t(n?.message ?? n?.error ?? (e instanceof Error ? e.message : "Action failed.")), null;
  } finally {
    e("");
  }
}
function ls({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), [u, d] = (0, C.useState)(""), [f, p] = (0, C.useState)("fleet"), [m, h] = (0, C.useState)("linux"), [g, _] = (0, C.useState)(null), [v, y] = (0, C.useState)([]), [b, x] = (0, C.useState)([]), [S, w] = (0, C.useState)(!1), T = e.agents.filter((e) => Q(e, ["status"]) === "online").length, E = e.targetGroups[0] ?? null, D = _i("agents").map((e) => ({
    id: e.id,
    label: e.label
  })), ee = fi(e.state), te = ns(g, ["summary"]), ne = ni(e.state?.readiness), ie = Array.isArray(g?.reviews) ? g.reviews : [], ae = pi(e.audit), oe = [
    {
      key: "id",
      label: "ID",
      render: (e) => /* @__PURE__ */ (0, R.jsx)("code", { children: Q(e, ["id"]) })
    },
    {
      key: "health",
      label: "Health",
      render: (e) => {
        let t = ui(e);
        return /* @__PURE__ */ (0, R.jsx)(z, {
          tone: t === "online" ? "success" : t === "revoked" ? "danger" : "muted",
          children: t
        });
      }
    },
    {
      key: "version",
      label: "Version",
      render: (e) => Q(e, ["version", "agent_version"], "—")
    },
    {
      key: "placement",
      label: "Placement",
      render: (e) => li(e)
    },
    {
      key: "last_heartbeat",
      label: "Last heartbeat",
      render: (e) => I(e.last_heartbeat_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Q(e, ["id"], ""), n = Q(e, ["status"]) === "revoked";
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(V, {
            size: "sm",
            variant: "secondary",
            href: Mr("agent-detail", t),
            children: "Detail"
          }), n ? null : /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "danger",
            disabled: i !== "",
            onClick: () => void de(t),
            children: "Revoke"
          })]
        });
      }
    }
  ], k = [
    {
      key: "name",
      label: "Agent",
      render: (e) => Q(e, [
        "hostname",
        "name",
        "id"
      ])
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: Q(e, ["status"]) === "online" ? "success" : "muted",
        children: Q(e, ["status"], "unknown")
      })
    },
    {
      key: "freshness",
      label: "Heartbeat freshness",
      render: (e) => di(e)
    },
    {
      key: "heartbeat",
      label: "Last heartbeat",
      render: (e) => I(e.last_heartbeat_at)
    },
    {
      key: "version",
      label: "Version",
      render: (e) => Q(e, ["version"], "—")
    },
    {
      key: "fingerprint",
      label: "Gateway fingerprint",
      render: (e) => Q(e, ["fingerprint"], "not registered")
    }
  ], A = [
    {
      key: "name",
      label: "Agent",
      render: (e) => Q(e, [
        "hostname",
        "name",
        "id"
      ])
    },
    {
      key: "capabilities",
      label: "Observation modes",
      render: (e) => ci(e)
    },
    {
      key: "environment",
      label: "Environment",
      render: (e) => Q(e, ["environment_id"], "tenant scope")
    },
    {
      key: "group",
      label: "Target group",
      render: (e) => Q(e, ["target_group_id"], "unbound")
    }
  ], ce = [
    {
      key: "version",
      label: "Version",
      render: (e) => Q(e, ["version"])
    },
    {
      key: "channel",
      label: "Channel",
      render: (e) => Q(e, ["channel"], "stable")
    },
    {
      key: "state",
      label: "State",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: Q(e, ["state"], "active")
      })
    },
    {
      key: "rollout",
      label: "Rollout",
      render: (e) => `${rs(e, ["rollout", "percentage"], 100)}%`
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Q(e, ["id"], "");
        return e.rollback && Q(e, ["state"]) !== "rollback_requested" ? /* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: "secondary",
          disabled: i !== "",
          onClick: () => void fe(t),
          children: "Request rollback"
        }) : /* @__PURE__ */ (0, R.jsx)("span", {
          className: "muted",
          children: "—"
        });
      }
    }
  ], j = [
    {
      key: "name",
      label: "Name",
      render: (e) => Q(e, ["name"])
    },
    {
      key: "fingerprint",
      label: "Fingerprint",
      render: (e) => /* @__PURE__ */ (0, R.jsx)("code", { children: Q(e, ["fingerprint_sha256"]) })
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: Q(e, ["status"]) === "active" ? "success" : "muted",
        children: Q(e, ["status"])
      })
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Q(e, ["id"], "");
        return Q(e, ["status"]) === "active" ? /* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: "danger",
          disabled: i !== "",
          onClick: () => void me(t),
          children: "Revoke"
        }) : /* @__PURE__ */ (0, R.jsx)("span", {
          className: "muted",
          children: "revoked"
        });
      }
    }
  ], le = [
    {
      key: "action",
      label: "Action",
      render: (e) => Q(e, ["action"])
    },
    {
      key: "resource",
      label: "Resource",
      render: (e) => `${Q(e, ["resource_type"])}:${Q(e, ["resource_id"])}`
    },
    {
      key: "actor",
      label: "Actor",
      render: (e) => Q(e, ["actor_role"], "system")
    },
    {
      key: "when",
      label: "Recorded",
      render: (e) => I(e.created_at ?? e.timestamp)
    }
  ];
  (0, C.useEffect)(() => {
    if (![
      "placement",
      "install",
      "fleet"
    ].includes(f)) return;
    let e = !1;
    return w(!0), L(t, n, "/v1/placement/reviews").then((t) => {
      e || _(t);
    }).catch(() => {
      e || _(null);
    }).finally(() => {
      e || w(!1);
    }), () => {
      e = !0;
    };
  }, [
    f,
    t,
    n
  ]), (0, C.useEffect)(() => {
    if (f !== "upgrades") return;
    let e = !1;
    return w(!0), Promise.all([L(t, n, "/v1/agent-updates"), L(t, n, "/v1/agent-update-trust-keys")]).then(([t, n]) => {
      if (e) return;
      let r = Array.isArray(t.items) ? t.items : [], i = Array.isArray(n.items) ? n.items : [];
      y(r), x(i);
    }).catch(() => {
      e || (y([]), x([]));
    }).finally(() => {
      e || w(!1);
    }), () => {
      e = !0;
    };
  }, [
    f,
    t,
    n
  ]);
  async function ue() {
    let e = {
      name: "agent-install",
      expires_in_minutes: 60,
      max_registrations: 1
    }, i = Q(E, ["environment_id"], ""), o = Q(E, ["id"], "");
    i && (e.environment_id = i), o && (e.target_group_id = o);
    let c = await cs(a, l, s, "create-bootstrap-token", () => L(t, n, "/v1/bootstrap-tokens", {
      method: "POST",
      body: e
    }), "Bootstrap token created. Copy the one-time secret now.", r), u = Q(c, ["secret"], Qo(c, ["token", "secret"], ""));
    u && d(u);
  }
  async function de(e) {
    e && await cs(a, l, s, `revoke-${e}`, () => L(t, n, `/v1/agents/${e}/revoke`, { method: "POST" }), "Agent revoked. Heartbeat and jobs will be rejected.", r);
  }
  async function fe(e) {
    e && await cs(a, l, s, `rollback-${e}`, () => L(t, n, `/v1/agent-updates/${e}/rollback`, { method: "POST" }), "Rollback requested for eligible agents.", async () => {
      let e = await L(t, n, "/v1/agent-updates");
      y(Array.isArray(e.items) ? e.items : []), await r();
    });
  }
  async function me(e) {
    e && await cs(a, l, s, `trust-revoke-${e}`, () => L(t, n, `/v1/agent-update-trust-keys/${e}/revoke`, { method: "POST" }), "Trust key revoked.", async () => {
      let e = await L(t, n, "/v1/agent-update-trust-keys");
      x(Array.isArray(e.items) ? e.items : []), await r();
    });
  }
  async function he(e) {
    e.preventDefault();
    let i = new FormData(e.currentTarget);
    await cs(a, l, s, "add-trust-key", () => L(t, n, "/v1/agent-update-trust-keys", {
      method: "POST",
      body: {
        name: String(i.get("name") ?? "").trim() || "agent update signing key",
        public_key_der_base64: String(i.get("public_key_der_base64") ?? "").trim()
      }
    }), "Trust key registered.", async () => {
      let i = await L(t, n, "/v1/agent-update-trust-keys");
      x(Array.isArray(i.items) ? i.items : []), e.currentTarget.reset(), await r();
    });
  }
  let ge = u || "<BOOTSTRAP_TOKEN>", _e = mi();
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: "agents" }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Declared groups",
            value: e.targetGroups.length,
            sub: "Manual or API import only",
            icon: ke,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Agents",
            value: e.agents.length,
            sub: "Outbound-only control channel",
            icon: re,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Online agents",
            value: T,
            sub: "Current heartbeat status",
            icon: Se,
            tone: T > 0 ? "success" : "muted"
          })
        ]
      }),
      (o || c) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c ? "form-banner error" : "form-banner",
        children: c || o
      }),
      /* @__PURE__ */ (0, R.jsx)("div", {
        className: "row-actions",
        style: { marginBottom: "0.75rem" },
        children: /* @__PURE__ */ (0, R.jsx)(B, {
          disabled: i !== "",
          onClick: () => void ue(),
          children: "Create bootstrap token"
        })
      }),
      /* @__PURE__ */ (0, R.jsx)(Ar, {
        value: f,
        options: D,
        onChange: p,
        className: "tabs-wrap"
      }),
      f === "install" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Install outbound agent" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Create a bootstrap token, then run the install command on your host. No inbound management port is required." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "product-form",
          children: [
            /* @__PURE__ */ (0, R.jsx)(Ar, {
              value: m,
              options: [
                {
                  id: "linux",
                  label: "Linux"
                },
                {
                  id: "docker",
                  label: "Docker"
                },
                {
                  id: "helm",
                  label: "Helm"
                }
              ],
              onChange: h,
              className: "tabs-wrap"
            }),
            m === "linux" ? /* @__PURE__ */ (0, R.jsx)("pre", {
              className: "codeblock",
              children: `curl -fsSL ${_e}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${_e}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${ge}" bash`
            }) : null,
            m === "docker" ? /* @__PURE__ */ (0, R.jsx)("pre", {
              className: "codeblock",
              children: `docker run -d --name astranull-agent \\
  -e ASTRANULL_API_URL="${_e}" \\
  -e ASTRANULL_BOOTSTRAP_TOKEN="${ge}" \\
  astranull/agent:latest`
            }) : null,
            m === "helm" ? /* @__PURE__ */ (0, R.jsx)("pre", {
              className: "codeblock",
              children: `helm upgrade --install astranull-agent ./charts/agent \\
  --namespace astranull --create-namespace \\
  --set apiUrl="${_e}" \\
  --set bootstrapToken="${ge}"`
            }) : null,
            u ? /* @__PURE__ */ (0, R.jsx)("p", {
              className: "muted",
              children: "One-time token shown. It will not be displayed again after refresh."
            }) : null
          ]
        })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Placement diagnostics" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "From ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/placement/reviews" }),
          " and readiness placement factor."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Placement factor" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ee == null ? "Awaiting evidence" : `${ee}%` })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Online agents" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: T })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Proven groups" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: rs(te, ["proven"], ts(ne ?? {}, ["proven"], 0)) })] }),
            /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Misplaced risk" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: rs(te, ["misplaced_risk"], ts(ne ?? {}, ["misplaced_risk"], 0)) })] })
          ]
        })] })]
      }) : null,
      f === "fleet" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent fleet" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Rows from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents" }),
        ". Revoke invalidates credentials immediately."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: oe,
        items: e.agents,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: re,
          title: "No agents have registered yet.",
          body: "Create a bootstrap token on the Install tab, then install an outbound-only agent."
        })
      }) })] }) : null,
      f === "health" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent health" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Heartbeat freshness and gateway trust metadata from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents" }),
        "."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: k,
        items: e.agents,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: O,
          title: "No agents to monitor.",
          body: "Register an agent to see heartbeat freshness and version posture."
        })
      }) })] }) : null,
      f === "placement" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Placement reviews" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Per target-group placement confidence from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/placement/reviews" }),
        "."
      ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
        S ? /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: "Loading placement reviews…"
        }) : null,
        !S && ie.length === 0 ? /* @__PURE__ */ (0, R.jsx)(q, {
          icon: ke,
          title: "No placement reviews yet.",
          body: "Declare target groups and register agents to compute placement confidence."
        }) : null,
        ie.length > 0 ? /* @__PURE__ */ (0, R.jsx)("div", {
          className: "kv-list",
          children: ie.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Q(e, ["target_group_name", "target_group_id"], "group") }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(e, ["status"], "unknown") })] }, Q(e, ["target_group_id"], Q(e, ["group_id"]))))
        }) : null,
        te ? /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: Q(te, ["summary"], "Placement diagnostics computed from declared scope and agent evidence.")
        }) : null
      ] })] }) : null,
      f === "capabilities" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent capabilities" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Observation modes reported on registration and heartbeat via ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents" }),
        "."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: A,
        items: e.agents,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: pe,
          title: "No capability reports yet.",
          body: "Capabilities appear after the first agent heartbeat."
        })
      }) })] }) : null,
      f === "logs" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Agent audit trail" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
        "Metadata-only lifecycle events from ",
        /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/audit-log" }),
        " (not host operational logs)."
      ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: le,
        items: ae,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: se,
          title: "No agent audit events yet.",
          body: "Registration, heartbeat, revoke, and update actions appear here after agents connect."
        })
      }) })] }) : null,
      f === "upgrades" ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Release rollout" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Tenant releases from ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agent-updates" }),
          ". Agents poll ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agents/:id/update" }),
          "."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [S ? /* @__PURE__ */ (0, R.jsx)("p", {
          className: "muted",
          children: "Loading releases…"
        }) : null, /* @__PURE__ */ (0, R.jsx)(J, {
          columns: ce,
          items: v,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: re,
            title: "No agent releases published.",
            body: "Release creation uses signed manifests and HTTPS distribution URLs via operator packaging workflows or POST /v1/agent-updates."
          })
        })] })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Trust keys" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Ed25519 signing keys from ",
          /* @__PURE__ */ (0, R.jsx)("code", { children: "GET /v1/agent-update-trust-keys" }),
          "."
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "product-form",
          children: [/* @__PURE__ */ (0, R.jsx)(J, {
            columns: j,
            items: b,
            empty: /* @__PURE__ */ (0, R.jsx)(q, {
              icon: M,
              title: "No trust keys registered.",
              body: "Add the public key from your agent update signing ceremony."
            })
          }), /* @__PURE__ */ (0, R.jsxs)("form", {
            className: "product-form",
            onSubmit: (e) => void he(e),
            children: [
              /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Key name" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "name",
                placeholder: "production signing key"
              })] }),
              /* @__PURE__ */ (0, R.jsxs)("label", {
                className: "full",
                children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Public key (DER base64)" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                  name: "public_key_der_base64",
                  rows: 3,
                  placeholder: "MCowBQYDK2VwAyEA…",
                  required: !0
                })]
              }),
              /* @__PURE__ */ (0, R.jsx)("div", {
                className: "form-actions full",
                children: /* @__PURE__ */ (0, R.jsx)(B, {
                  type: "submit",
                  disabled: i !== "",
                  children: "Register trust key"
                })
              })
            ]
          })]
        })] })]
      }) : null
    ]
  });
}
function us({ route: e, data: t, config: n, session: r, onRefresh: i }) {
  let [a, o] = (0, C.useState)(""), [s, c] = (0, C.useState)(""), [l, u] = (0, C.useState)(""), [d, f] = (0, C.useState)("recommended"), [p, m] = (0, C.useState)("all"), [h, g] = (0, C.useState)(() => Q(t.runs[0] ?? {}, ["id"], "")), [_, v] = (0, C.useState)("summary"), [y, b] = (0, C.useState)(() => Q(t.findings[0] ?? {}, ["id"], "")), [x, S] = (0, C.useState)("open"), [w, T] = (0, C.useState)(() => Q(t.evidence[0] ?? {}, ["id"], "")), [E, D] = (0, C.useState)(null), [ee, te] = (0, C.useState)([]), [ne, re] = (0, C.useState)(null), [ie, ae] = (0, C.useState)(null), [oe, A] = (0, C.useState)(""), [se, le] = (0, C.useState)(null), ue = t.targetGroups[0] ?? null, M = t.checks.find((e) => Q(e, ["safety_class"]) === "safe") ?? null, de = (0, C.useMemo)(() => Bo(t.checks), [t.checks]), fe = (0, C.useMemo)(() => zo(t.checks, d, p), [
    t.checks,
    d,
    p
  ]);
  (0, C.useEffect)(() => {
    !h && t.runs[0] && g(Q(t.runs[0], ["id"], ""));
  }, [t.runs, h]), (0, C.useEffect)(() => {
    !w && t.evidence[0] && T(Q(t.evidence[0], ["id"], ""));
  }, [t.evidence, w]), (0, C.useEffect)(() => {
    !y && t.findings[0] && b(Q(t.findings[0], ["id"], ""));
  }, [t.findings, y]), (0, C.useEffect)(() => {
    v("summary");
  }, [h]), (0, C.useEffect)(() => {
    if (e !== "runs" || !h) {
      D(null), te([]);
      return;
    }
    let t = !1;
    return Promise.all([L(n, r, `/v1/test-runs/${h}`), L(n, r, `/v1/test-runs/${h}/events`)]).then(([e, n]) => {
      if (t) return;
      D(e);
      let r = Array.isArray(n.items) ? n.items : [];
      te(r);
    }).catch(() => {
      t || (D(null), te([]));
    }), () => {
      t = !0;
    };
  }, [
    e,
    h,
    n,
    r,
    t.runs
  ]), (0, C.useEffect)(() => {
    if (e !== "findings" || !y) {
      re(null);
      return;
    }
    let t = !1;
    return L(n, r, `/v1/findings/${y}`).then((e) => {
      t || re(e);
    }).catch(() => {
      t || re(null);
    }), () => {
      t = !0;
    };
  }, [
    e,
    y,
    n,
    r
  ]), (0, C.useEffect)(() => {
    if (e !== "evidence" || !w) {
      ae(null);
      return;
    }
    let t = !1;
    return L(n, r, `/v1/evidence/${w}`).then((e) => {
      t || ae(e);
    }).catch(() => {
      t || ae(null);
    }), () => {
      t = !0;
    };
  }, [
    e,
    w,
    n,
    r
  ]);
  async function me(e) {
    let t = Q(ue, ["id"], ""), a = e ?? Q(M ?? {}, ["check_id"], "");
    if (!t || !a) {
      u("Declare a target group and safe check before starting a run.");
      return;
    }
    let s = await L(n, r, `/v1/target-groups/${t}`), l = Q((Array.isArray(s.targets) ? s.targets : [])[0] ?? {}, ["id"], "");
    if (!l) {
      u("Add at least one target to the declared group before starting a run.");
      return;
    }
    let d = await cs(o, u, c, "start-safe-run", () => L(n, r, "/v1/test-runs", {
      method: "POST",
      body: {
        target_group_id: t,
        target_id: l,
        check_id: a
      }
    }), "Safe validation run started.", i);
    if (d && typeof d == "object") {
      let e = d.run ?? d;
      g(Q(e, ["id"], ""));
    }
  }
  async function he(e) {
    e && await cs(o, u, c, `cancel-${e}`, () => L(n, r, `/v1/test-runs/${e}/cancel`, { method: "POST" }), "Run cancelled.", i);
  }
  async function ge(e) {
    e && await cs(o, u, c, `finalize-${e}`, () => L(n, r, `/v1/test-runs/${e}/finalize`, { method: "POST" }), "Run finalized after observation window.", i);
  }
  async function _e(e, t, a) {
    e && await cs(o, u, c, `finding-${e}`, () => L(n, r, `/v1/findings/${e}`, {
      method: "PATCH",
      body: t
    }), a, i);
  }
  async function ve(e) {
    let t = Q(e, ["id"], ""), a = Oo(e);
    if (!a) {
      u("Finding is missing retest context (check_id, waf asset, or CVE pipeline item).");
      return;
    }
    if (a.kind === "waf-validation") {
      await cs(o, u, c, `retest-waf-${t}`, () => L(n, r, "/v1/waf/validations", {
        method: "POST",
        body: {
          waf_asset_id: a.wafAssetId,
          modes: ["marker"]
        }
      }), "WAF validation retest started.", i);
      return;
    }
    if (a.kind === "cve-retest") {
      await cs(o, u, c, `retest-cve-${t}`, () => L(n, r, `/v1/waf/cve-pipeline/${encodeURIComponent(a.pipelineId)}/retest`, { method: "POST" }), "CVE pipeline retest started.", i);
      return;
    }
    if (a.kind === "cve-retest-url") {
      await cs(o, u, c, `retest-cve-url-${t}`, () => L(n, r, a.retestUrl, { method: "POST" }), "CVE retest started.", i);
      return;
    }
    await me(a.checkId);
  }
  async function ye() {
    if (!t.evidence.length) {
      u("No evidence records available to export.");
      return;
    }
    o("export-evidence-chain"), u(""), c("");
    try {
      let e = [];
      for (let i of t.runs.slice(-20)) {
        let t = Q(i, ["id"], "");
        if (t) try {
          let i = (await L(n, r, `/v1/test-runs/${t}`)).verdict;
          i && e.push({
            ...i,
            test_run_id: t
          });
        } catch {}
      }
      let i = uo({
        evidence: t.evidence,
        runs: t.runs,
        verdicts: e,
        findings: t.findings
      }), a = await co(i.payload, r.tenant_id ?? "ten_demo"), o = await L(n, r, "/v1/custody/verify", {
        method: "POST",
        body: {
          payload: i.payload,
          custody: a
        }
      });
      A(i.json), le(ns(o, ["verification"]) ?? o), c("Evidence chain exported and custody digest verified."), await navigator.clipboard.writeText(i.json).catch(() => void 0);
    } catch (e) {
      u(e instanceof Error ? e.message : "Evidence chain export failed."), le(null);
    } finally {
      o("");
    }
  }
  async function be(e) {
    if (e) {
      o(`export-finding-${e}`), u("");
      try {
        let t = await L(n, r, `/v1/findings/${e}/export`, { method: "POST" });
        A(JSON.stringify(t, null, 2)), c("Finding export generated with custody manifest.");
      } catch (e) {
        u(e instanceof Error ? e.message : "Export failed.");
      } finally {
        o("");
      }
    }
  }
  if (e === "checks") {
    let e = _i("checks").map((e) => ({
      id: e.id,
      label: e.label
    })), t = ko.map((e) => ({
      id: e.id,
      label: `${e.label} (${de[e.id]})`
    }));
    return /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "content",
      children: [
        /* @__PURE__ */ (0, R.jsx)(ia, { route: "checks" }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "metric-grid three",
          children: [
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "Catalog checks",
              value: de.all,
              sub: "Versioned catalog from API",
              icon: pe,
              tone: "info"
            }),
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "Safe checks",
              value: de.safe,
              sub: "Customer-runnable",
              icon: N,
              tone: "success"
            }),
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "SOC-only",
              value: de.soc,
              sub: "Request via high-scale",
              icon: De,
              tone: "muted"
            })
          ]
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Check library" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Rows from `/v1/checks`. Use All/Safe/SOC scope tabs with family tabs below. SOC-gated checks remain request-only for customers." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
          /* @__PURE__ */ (0, R.jsx)(Ar, {
            value: p,
            options: t,
            onChange: m,
            className: "tabs-wrap"
          }),
          /* @__PURE__ */ (0, R.jsx)(Ar, {
            value: d,
            options: e,
            onChange: f,
            className: "tabs-wrap"
          }),
          /* @__PURE__ */ (0, R.jsx)(J, {
            columns: [
              {
                key: "check",
                label: "Check",
                render: (e) => Q(e, ["name", "check_id"])
              },
              {
                key: "family",
                label: "Family",
                render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                  tone: "info",
                  children: es(Q(e, ["vector_family"]))
                })
              },
              {
                key: "safety",
                label: "Safety",
                render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                  tone: Q(e, ["safety_class"]) === "safe" ? "success" : "warn",
                  children: Q(e, ["safety_class"])
                })
              },
              {
                key: "description",
                label: "Description",
                render: (e) => Q(e, ["description"])
              },
              {
                key: "probe",
                label: "Probe profile",
                render: (e) => Q(e, ["probe_profile", "kind"])
              }
            ],
            items: fe,
            empty: d === "custom" ? /* @__PURE__ */ (0, R.jsx)(q, {
              icon: pe,
              title: "No custom checks in catalog.",
              body: "Customer-defined safe checks bind through test policies after staff-reviewed scope declaration.",
              actionLabel: "Open test policies",
              actionHref: "#test-policies"
            }) : /* @__PURE__ */ (0, R.jsx)(q, {
              icon: pe,
              title: "No checks in this family.",
              body: "The check catalog loads from `/v1/checks` after tenant bootstrap."
            })
          })
        ] })] })
      ]
    });
  }
  if (e === "runs") {
    let e = [
      {
        key: "id",
        label: "Run",
        render: (e) => Q(e, ["id"])
      },
      {
        key: "check",
        label: "Check",
        render: (e) => Q(e, ["check_id"])
      },
      {
        key: "status",
        label: "Status",
        render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
          tone: Q(e, ["status"]) === "verdicted" ? "success" : "warn",
          children: Q(e, ["status"])
        })
      },
      {
        key: "verdict",
        label: "Verdict",
        render: (e) => Q(e, ["verdict", "verdict"], "pending")
      },
      {
        key: "time",
        label: "Started",
        render: (e) => I(e.started_at ?? e.created_at)
      },
      {
        key: "actions",
        label: "Actions",
        render: (e) => {
          let t = Q(e, ["id"], ""), n = Q(e, ["status"], ""), r = [
            "planned",
            "running",
            "collecting"
          ].includes(n);
          return /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "row-actions",
            children: [
              /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: t === h ? "default" : "secondary",
                onClick: () => g(t),
                children: "Detail"
              }),
              /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: Mr("run-detail", t),
                children: "Open"
              }),
              r ? /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "danger",
                disabled: a !== "",
                onClick: () => void he(t),
                children: "Cancel"
              }) : null,
              r ? /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "ghost",
                disabled: a !== "",
                onClick: () => void ge(t),
                children: "Finalize"
              }) : null
            ]
          });
        }
      }
    ], n = E?.verdict, r = _i("runs").map((e) => ({
      id: e.id,
      label: e.label
    })), i = ee.filter((e) => Q(e, ["signal_type"]) === "probe_result"), o = ee.filter((e) => ["agent_observation", "agent_no_observation"].includes(Q(e, ["signal_type"]))), c = t.evidence.filter((e) => Q(e, ["test_run_id"], "") === h), u = t.findings.filter((e) => Q(e, ["test_run_id"], "") === h);
    return /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "content",
      children: [
        /* @__PURE__ */ (0, R.jsx)(ia, { route: "runs" }),
        (s || l) && /* @__PURE__ */ (0, R.jsx)("div", {
          className: l ? "form-banner error" : "form-banner",
          children: l || s
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Start safe validation" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Creates a bounded run against the first declared target in the first active target group." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(B, {
          disabled: a !== "" || !ue || !M,
          onClick: () => void me(),
          children: a === "start-safe-run" ? "Starting..." : "Start safe run"
        }) })] }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Test runs" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "From `/v1/test-runs` with live detail, events, cancel, and finalize." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: e,
          items: t.runs,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: O,
            title: "No test runs yet.",
            body: "Start a safe validation run after declaring target scope.",
            actionLabel: "Open onboarding",
            actionHref: "#onboarding"
          })
        }) })] }),
        E ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Run detail" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          h,
          " · ",
          Q(E, ["check_id"]),
          " · ",
          Q(E, ["status"])
        ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
          /* @__PURE__ */ (0, R.jsx)(Ar, {
            value: _,
            options: r,
            onChange: v,
            className: "tabs-wrap"
          }),
          _ === "summary" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "kv-list",
              children: [
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(E, ["status"]) })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Check" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(E, ["check_id"]) })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(E, ["target_group_id"]) })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(E, ["target_id"]) })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Vector" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(E, ["vector_family"], "—") })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Safety" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(E, ["safety_class"], "—") })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Verdict" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(n ?? {}, ["verdict"], "pending") })] }),
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Placement confidence" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Qo(n ?? {}, ["placement_confidence", "level"], "—") })] })
              ]
            }),
            /* @__PURE__ */ (0, R.jsx)(Zr, {
              detail: E,
              events: ee
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "row-actions",
              style: { marginTop: "1rem" },
              children: /* @__PURE__ */ (0, R.jsx)(V, {
                size: "sm",
                variant: "secondary",
                href: Mr("run-detail", h),
                children: "Open full detail"
              })
            })
          ] }) : null,
          _ === "timeline" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)(Xr, { events: ee }), ee.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No events recorded yet."
          }) : /* @__PURE__ */ (0, R.jsx)("div", {
            className: "timeline-list",
            children: ee.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: t + 1 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: Q(e, ["signal_type", "type"]) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
              I(e.timestamp ?? e.created_at),
              " — ",
              Q(e, ["source"], "system")
            ] })] })] }, Q(e, ["id"], String(t))))
          })] }) : null,
          _ === "probe-results" ? i.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No probe_result events for this run."
          }) : /* @__PURE__ */ (0, R.jsx)("div", {
            className: "kv-list",
            children: i.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: I(e.timestamp ?? e.created_at) }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Qo(e, ["metadata", "external_result"], Q(e, ["external_result"], Q(e, ["source"], "probe_result"))) })] }, Q(e, ["id"], String(t))))
          }) : null,
          _ === "agent-observations" ? o.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No agent observation events for this run."
          }) : /* @__PURE__ */ (0, R.jsx)("div", {
            className: "kv-list",
            children: o.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Q(e, ["signal_type"]) }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [
              Q(e, ["agent_id"], Q(e, ["source"], "agent")),
              " · ",
              I(e.timestamp ?? e.created_at)
            ] })] }, Q(e, ["id"], String(t))))
          }) : null,
          _ === "correlation" ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)(Jr, {
            detail: E,
            events: ee
          }), /* @__PURE__ */ (0, R.jsx)(Yr, { detail: E })] }) : null,
          _ === "evidence" ? c.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No evidence records linked to this run yet."
          }) : /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)("div", {
            className: "kv-list",
            children: c.map((e) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: Q(e, ["kind", "signal_type"], "evidence") }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(e, ["id"]) })] }, Q(e, ["id"], "")))
          }), u.length > 0 ? /* @__PURE__ */ (0, R.jsx)("div", {
            className: "row-actions",
            style: { marginTop: "1rem" },
            children: /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "ghost",
              href: "#findings",
              children: "Open findings"
            })
          }) : null] }) : null,
          _ === "events" ? ee.length === 0 ? /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No events recorded yet."
          }) : /* @__PURE__ */ (0, R.jsx)("div", {
            className: "timeline-list",
            children: ee.map((e, t) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: t + 1 }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: Q(e, ["signal_type", "type"]) }), /* @__PURE__ */ (0, R.jsxs)("p", { children: [
              I(e.timestamp ?? e.created_at),
              " · ",
              Q(e, ["source"], "system"),
              " · ",
              Q(e, ["agent_id"], "—")
            ] })] })] }, Q(e, ["id"], String(t))))
          }) : null
        ] })] }) : null
      ]
    });
  }
  if (e === "findings") {
    let e = wo(t.findings), i = _i("findings").map((e) => ({
      id: e.id,
      label: e.label
    })), o = To(t.findings, x, t.checks), c = Eo(o, t.targetGroups), u = Do(o, t.checks), d = [
      {
        key: "title",
        label: "Finding",
        render: (e) => Q(e, ["title", "id"])
      },
      {
        key: "severity",
        label: "Severity",
        render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
          tone: ["critical", "high"].includes(Q(e, ["severity"]).toLowerCase()) ? "danger" : "warn",
          children: Q(e, ["severity"])
        })
      },
      {
        key: "status",
        label: "Status",
        render: (e) => Q(e, ["status"])
      },
      {
        key: "assignee",
        label: "Assignee",
        render: (e) => Q(e, ["assignee"], "—")
      },
      ...x === "target-group" ? [{
        key: "target-group",
        label: "Target group",
        render: (e) => Q(e, ["target_group_id"], "—")
      }] : [],
      ...x === "vector" ? [{
        key: "vector",
        label: "Vector",
        render: (e) => es(Q(e, ["vector_family"], Q(t.checks.find((t) => Q(t, ["check_id"]) === Q(e, ["check_id"], "")) ?? {}, ["vector_family"], "other")))
      }] : [],
      ...x === "sla" ? [{
        key: "sla",
        label: "SLA",
        render: (e) => {
          let t = bo(e);
          return t ? /* @__PURE__ */ (0, R.jsxs)(z, {
            tone: xo(e) ? "danger" : "warn",
            children: ["Due ", I(t)]
          }) : "—";
        }
      }] : [],
      {
        key: "time",
        label: "Updated",
        render: (e) => I(e.updated_at ?? e.created_at)
      },
      {
        key: "actions",
        label: "Actions",
        render: (e) => {
          let t = Q(e, ["id"], "");
          return /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "row-actions",
            children: [
              /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: t === y ? "default" : "secondary",
                onClick: () => b(t),
                children: "Detail"
              }),
              /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "ghost",
                disabled: a !== "",
                onClick: () => void _e(t, { status: "accepted_risk" }, "Finding marked accepted risk."),
                children: "Accept risk"
              }),
              /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "ghost",
                disabled: a !== "",
                onClick: () => void _e(t, { status: "closed" }, "Finding closed."),
                children: "Close"
              }),
              /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "ghost",
                disabled: a !== "",
                onClick: () => void ve(e),
                children: "Retest"
              })
            ]
          });
        }
      }
    ], f = /* @__PURE__ */ (0, R.jsx)(q, {
      icon: Ae,
      title: `No ${i.find((e) => e.id === x)?.label.toLowerCase() ?? "matching"} findings.`,
      body: "Findings appear after failing verdicts are published and triaged."
    }), p = (e) => /* @__PURE__ */ (0, R.jsx)(J, {
      columns: d,
      items: e,
      empty: f
    });
    return /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "content",
      children: [
        /* @__PURE__ */ (0, R.jsx)(ia, { route: "findings" }),
        /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "metric-grid",
          children: [
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "Open findings",
              value: e.openCount,
              sub: e.openSeverityBreakdown,
              icon: Ae,
              tone: e.openCount > 0 ? "warn" : "success"
            }),
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "Accepted risk",
              value: e.acceptedRiskCount,
              sub: "Owner-approved exceptions",
              icon: N,
              tone: e.acceptedRiskCount > 0 ? "info" : "muted"
            }),
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "Closed (30d)",
              value: e.closed30dCount,
              sub: "Resolved within the last 30 days",
              icon: k,
              tone: e.closed30dCount > 0 ? "success" : "muted"
            }),
            /* @__PURE__ */ (0, R.jsx)(X, {
              label: "SLA breach",
              value: e.slaBreachCount,
              sub: "Open findings past severity window",
              icon: ce,
              tone: e.slaBreachCount > 0 ? "danger" : "success"
            })
          ]
        }),
        (s || l) && /* @__PURE__ */ (0, R.jsx)("div", {
          className: l ? "form-banner error" : "form-banner",
          children: l || s
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Findings" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Evidence-backed gaps from `/v1/findings` with triage tabs, assignee workflow, export, and retest actions." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [/* @__PURE__ */ (0, R.jsx)(Ar, {
          value: x,
          options: i,
          onChange: S,
          className: "tabs-wrap"
        }), x === "target-group" ? c.length === 0 ? f : /* @__PURE__ */ (0, R.jsx)("div", {
          className: "finding-group-sections",
          children: c.map((e) => /* @__PURE__ */ (0, R.jsxs)("section", {
            className: "finding-group-section",
            children: [/* @__PURE__ */ (0, R.jsxs)("div", {
              className: "finding-group-header",
              children: [/* @__PURE__ */ (0, R.jsx)("h4", { children: e.label }), /* @__PURE__ */ (0, R.jsxs)(z, {
                tone: "info",
                children: [e.items.length, " open"]
              })]
            }), p(e.items)]
          }, e.groupId))
        }) : x === "vector" ? u.length === 0 ? f : /* @__PURE__ */ (0, R.jsx)("div", {
          className: "finding-group-sections",
          children: u.map((e) => /* @__PURE__ */ (0, R.jsxs)("section", {
            className: "finding-group-section",
            children: [/* @__PURE__ */ (0, R.jsxs)("div", {
              className: "finding-group-header",
              children: [/* @__PURE__ */ (0, R.jsx)("h4", { children: e.label }), /* @__PURE__ */ (0, R.jsxs)(z, {
                tone: "info",
                children: [e.items.length, " open"]
              })]
            }), p(e.items)]
          }, e.family))
        }) : p(o)] })] }),
        ne ? /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "split",
          children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Why this finding?" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
            Q(ne, ["title"]),
            " · ",
            Q(ne, ["severity"]),
            " · ",
            Q(ne, ["status"])
          ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(eo, {
            finding: ne,
            config: n,
            session: r
          }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Triage and assignee" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Assign owner and export custody-backed evidence." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [
            /* @__PURE__ */ (0, R.jsxs)("form", {
              className: "product-form",
              onSubmit: (e) => {
                e.preventDefault();
                let t = new FormData(e.currentTarget);
                _e(y, {
                  assignee: String(t.get("assignee") ?? "").trim(),
                  notes: String(t.get("notes") ?? "").trim()
                }, "Triage notes updated.");
              },
              children: [
                /* @__PURE__ */ (0, R.jsxs)("label", {
                  className: "full",
                  children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Assignee" }), /* @__PURE__ */ (0, R.jsx)("input", {
                    name: "assignee",
                    defaultValue: Q(ne, ["assignee"], "")
                  })]
                }),
                /* @__PURE__ */ (0, R.jsxs)("label", {
                  className: "full",
                  children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Triage notes" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                    name: "notes",
                    rows: 4,
                    defaultValue: Q(ne, ["notes"], ""),
                    placeholder: "Owner context, remediation plan, or accepted-risk rationale."
                  })]
                }),
                /* @__PURE__ */ (0, R.jsx)("div", {
                  className: "form-actions full",
                  children: /* @__PURE__ */ (0, R.jsx)(B, {
                    type: "submit",
                    disabled: a !== "",
                    children: "Save triage"
                  })
                })
              ]
            }),
            /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "row-actions",
              children: [/* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "secondary",
                disabled: a !== "",
                onClick: () => void be(y),
                children: "Export with custody"
              }), /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "ghost",
                disabled: a !== "",
                onClick: () => void ve(ne),
                children: "Start retest run"
              })]
            }),
            oe ? /* @__PURE__ */ (0, R.jsx)("pre", {
              className: "codeblock",
              children: oe
            }) : null
          ] })] })]
        }) : t.findings.length > 0 ? /* @__PURE__ */ (0, R.jsx)(H, { children: /* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Triage and assignee" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Select a finding to assign an owner or export custody-backed evidence." })] }) }) : null
      ]
    });
  }
  let xe = [
    {
      key: "id",
      label: "Evidence",
      render: (e) => Q(e, ["id"])
    },
    {
      key: "kind",
      label: "Kind",
      render: (e) => Q(e, [
        "label",
        "kind",
        "signal_type"
      ])
    },
    {
      key: "run",
      label: "Test run",
      render: (e) => Q(e, ["test_run_id"])
    },
    {
      key: "source",
      label: "Source",
      render: (e) => Q(e, ["source"], Qo(e, ["metadata", "simulation"], Qo(e, ["metadata", "vector_family"], "—")))
    },
    {
      key: "time",
      label: "Recorded",
      render: (e) => I(e.created_at ?? e.timestamp)
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = Q(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: t === w ? "default" : "secondary",
          onClick: () => T(t),
          children: "Detail"
        });
      }
    }
  ], Se = uo({
    evidence: t.evidence,
    runs: t.runs,
    findings: t.findings
  });
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: "evidence" }),
      (s || l) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: l ? "form-banner error" : "form-banner",
        children: l || s
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Evidence records",
            value: t.evidence.length,
            sub: "Custody-ready metadata",
            icon: j,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Linked runs",
            value: new Set(t.evidence.map((e) => Q(e, ["test_run_id"], "")).filter(Boolean)).size,
            sub: "Distinct test runs",
            icon: O,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Open findings",
            value: t.findings.filter((e) => Q(e, ["status"]) === "open").length,
            sub: "Related posture gaps",
            icon: Ae,
            tone: "warn"
          })
        ]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Evidence chain export" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Export correlated evidence, run, verdict, and finding links with custody verification through `/v1/custody/verify`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "product-form",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "row-actions",
            children: [/* @__PURE__ */ (0, R.jsx)(B, {
              disabled: a !== "" || t.evidence.length === 0,
              onClick: () => void ye(),
              children: "Export chain JSON"
            }), /* @__PURE__ */ (0, R.jsx)(B, {
              variant: "secondary",
              disabled: !oe,
              onClick: () => void navigator.clipboard.writeText(oe),
              children: "Copy export JSON"
            })]
          }),
          t.evidence.length > 0 ? /* @__PURE__ */ (0, R.jsx)("div", {
            className: "kv-list",
            children: fo(Se).map(([e, t]) => /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: e }), /* @__PURE__ */ (0, R.jsx)("strong", { children: t })] }, e))
          }) : null,
          se ? /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "kv-list",
            children: [
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Custody status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: se.ok === !0 ? "Digest verified" : Q(se, ["error"], "verification failed") })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Schema" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(se, ["schema_version"]) })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Digest" }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [Q(se, ["content_sha256"], "—").slice(0, 16), "…"] })] })
            ]
          }) : /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "No raw payloads or secrets are rendered in custody previews."
          })
        ]
      })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Evidence vault" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Metadata-only records from `/v1/evidence`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: xe,
        items: t.evidence,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: j,
          title: "No evidence yet.",
          body: "Evidence appears after probe and agent observations correlate."
        })
      }) })] }),
      t.evidence.length > 0 ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Evidence chain" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Correlated links between vault records, runs, and findings." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)("ol", {
        className: "dashboard-link-list",
        children: Se.payload.chain.slice(0, 12).map((e) => /* @__PURE__ */ (0, R.jsx)("li", { children: /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: String(e.evidence_id) }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [
          "run ",
          String(e.test_run_id ?? "—"),
          " · verdict ",
          String(e.verdict ?? "pending")
        ] })] }) }, String(e.evidence_id)))
      }) })] }) : null,
      ie ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Evidence detail" }), /* @__PURE__ */ (0, R.jsx)(G, { children: w })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Kind" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(ie, [
            "label",
            "kind",
            "signal_type"
          ]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Source" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(ie, ["source"], Qo(ie, ["metadata", "simulation"], Qo(ie, ["metadata", "vector_family"], "—"))) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Test run" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(ie, ["test_run_id"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Check" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(ie, ["check_id"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Created" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(ie.created_at) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Metadata keys" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Object.keys(ie.metadata ?? {}).join(", ") || "none" })] })
        ]
      })] }) : null,
      oe ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsx)(U, { children: /* @__PURE__ */ (0, R.jsx)(W, { children: "Export preview" }) }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("pre", {
        className: "codeblock",
        children: [oe.slice(0, 2400), oe.length > 2400 ? "\n…" : ""]
      }) })] }) : null
    ]
  });
}
function ds({ route: e, data: t, config: n, session: r, onRefresh: i }) {
  let [a, o] = (0, C.useState)(""), [s, c] = (0, C.useState)(""), [l, u] = (0, C.useState)(""), [d, f] = (0, C.useState)(""), [p, m] = (0, C.useState)("webhook"), [h, g] = (0, C.useState)(""), [_, v] = (0, C.useState)({}), [y, b] = (0, C.useState)({}), [x, S] = (0, C.useState)(() => Q(t.targetGroups[0] ?? null, ["id"], "")), [w, T] = (0, C.useState)([]), [E, D] = (0, C.useState)(!1), [O, ee] = (0, C.useState)("overview"), [te, ne] = (0, C.useState)(null), [re, ie] = (0, C.useState)({}), [ae, oe] = (0, C.useState)(() => Q(t.wafAssets[0] ?? {}, ["id"], "")), A = is(t, "waf_posture"), le = is(t, "external_discovery"), ue = [
    "waf-posture",
    "cve-pipeline",
    "supply-chain",
    "remediation"
  ].includes(e), M = e === "discovery" ? le : A, de = rs(t.wafCoverage, ["percentages", "protected"], 0), fe = t.targetGroups[0] ?? null, me = Q(t.findings[0] ?? {}, ["id"], ""), he = Q(fe, ["id"], "");
  (0, C.useEffect)(() => {
    if (e !== "waf-posture" || !x) {
      T([]);
      return;
    }
    let t = !1;
    return D(!0), L(n, r, `/v1/target-groups/${encodeURIComponent(x)}`).then((e) => {
      if (t) return;
      let n = Array.isArray(e.targets) ? e.targets : [];
      T(n);
    }).catch(() => {
      t || T([]);
    }).finally(() => {
      t || D(!1);
    }), () => {
      t = !0;
    };
  }, [
    e,
    x,
    n,
    r
  ]), (0, C.useEffect)(() => {
    if (e !== "waf-posture" || !A) {
      ne(null);
      return;
    }
    let t = !1;
    return L(n, r, "/v1/waf/drift-scans/latest").then((e) => {
      if (t) return;
      let n = e.scan_result;
      ne(n && typeof n == "object" ? n : null);
    }).catch(() => {
      t || ne(null);
    }), () => {
      t = !0;
    };
  }, [
    e,
    A,
    n,
    r,
    t.wafDriftEvents.length
  ]), (0, C.useEffect)(() => {
    !ae && t.wafAssets.length > 0 && oe(Q(t.wafAssets[0] ?? {}, ["id"], ""));
  }, [t.wafAssets, ae]);
  function _e(e, t) {
    return t[e] ?? he;
  }
  async function ve(e, t, n) {
    let r = await cs(o, u, c, e, t, n, i);
    return r && f(JSON.stringify(r, null, 2)), r;
  }
  let ye = {
    "waf-posture": {
      metricCards: [
        {
          label: "WAF assets",
          value: t.wafAssets.length,
          sub: "Declared protected services",
          icon: N,
          tone: "info"
        },
        {
          label: "Protected",
          value: `${Math.round(de)}%`,
          sub: `${ts(t.wafCoverage ?? {}, ["protected"])}/${ts(t.wafCoverage ?? {}, ["total_assets"])} assets`,
          icon: k,
          tone: de >= 80 ? "success" : "warn"
        },
        {
          label: "Drift events",
          value: t.wafDriftEvents.length,
          sub: "Posture changes",
          icon: Ae,
          tone: t.wafDriftEvents.length > 0 ? "warn" : "success"
        }
      ],
      columns: [
        {
          key: "asset",
          label: "Asset",
          render: (e) => Q(e, [
            "canonical_url",
            "display_ref",
            "id"
          ])
        },
        {
          key: "status",
          label: "Status",
          render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
            tone: Q(e, ["status"], "unknown") === "protected" ? "success" : "warn",
            children: Q(e, ["status"], "unknown")
          })
        },
        {
          key: "vendor",
          label: "Vendor",
          render: (e) => Q(e, [
            "detected_vendor",
            "expected_vendor_hint",
            "provider"
          ])
        },
        {
          key: "criticality",
          label: "Criticality",
          render: (e) => Q(e, ["business_criticality", "criticality"])
        },
        {
          key: "updated",
          label: "Updated",
          render: (e) => I(e.updated_at ?? e.created_at)
        },
        {
          key: "detail",
          label: "Detail",
          render: (e) => {
            let t = Q(e, ["id"], "");
            return t ? /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "secondary",
              href: Mr("waf-asset-detail", t),
              children: "Open"
            }) : null;
          }
        }
      ],
      items: t.wafAssets,
      emptyTitle: "No WAF assets recorded.",
      emptyBody: "Create a declared WAF asset or import from an approved connector snapshot."
    },
    "cve-pipeline": {
      metricCards: [
        {
          label: "CVE items",
          value: t.cvePipeline.length,
          sub: "Pipeline records",
          icon: Ae,
          tone: t.cvePipeline.length > 0 ? "warn" : "success"
        },
        {
          label: "Known exploited",
          value: t.cvePipeline.filter((e) => e.known_exploited === !0).length,
          sub: "KEV flagged",
          icon: De,
          tone: "danger"
        },
        {
          label: "Validations",
          value: t.wafValidations.length,
          sub: "Safe validation bindings",
          icon: pe,
          tone: "info"
        }
      ],
      columns: [
        {
          key: "cve",
          label: "CVE",
          render: (e) => Q(e, ["cve_id", "id"])
        },
        {
          key: "severity",
          label: "Severity",
          render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
            tone: ["critical", "high"].includes(Q(e, ["severity"]).toLowerCase()) ? "danger" : "warn",
            children: Q(e, ["severity"])
          })
        },
        {
          key: "stage",
          label: "Stage",
          render: (e) => Q(e, ["stage", "status"])
        },
        {
          key: "detail",
          label: "Detail",
          render: (e) => {
            let t = Q(e, ["id"], "");
            return t ? /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "secondary",
              href: Mr("cve-detail", t),
              children: "Open"
            }) : null;
          }
        },
        {
          key: "actions",
          label: "Actions",
          render: (e) => {
            let t = Q(e, ["id"], "");
            return /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "row-actions",
              children: [/* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "secondary",
                disabled: a !== "",
                onClick: () => void ve(`triage-${t}`, () => L(n, r, `/v1/waf/cve-pipeline/${t}/triage`, {
                  method: "POST",
                  body: {}
                }), "CVE item triaged."),
                children: "Triage"
              }), /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "ghost",
                disabled: a !== "",
                onClick: () => void ve(`validate-${t}`, () => L(n, r, `/v1/waf/cve-pipeline/${t}/validate`, { method: "POST" }), "Safe validation delegated."),
                children: "Validate"
              })]
            });
          }
        }
      ],
      items: t.cvePipeline,
      emptyTitle: "No CVE pipeline records.",
      emptyBody: "Ingest a feed or create a CVE item manually."
    },
    "supply-chain": {
      metricCards: [
        {
          label: "Risks",
          value: t.supplyChainRisks.length,
          sub: "Supply-chain records",
          icon: ge,
          tone: t.supplyChainRisks.length > 0 ? "warn" : "success"
        },
        {
          label: "High severity",
          value: t.supplyChainRisks.filter((e) => ["critical", "high"].includes(Q(e, ["severity"]).toLowerCase())).length,
          sub: "Needs review",
          icon: Ae,
          tone: "danger"
        },
        {
          label: "Authorized phases",
          value: t.supplyChainRisks.filter((e) => Array.isArray(e.phase_authorizations) && e.phase_authorizations.length > 0).length,
          sub: "Customer-approved",
          icon: j,
          tone: "info"
        }
      ],
      columns: [
        {
          key: "host",
          label: "Host",
          render: (e) => Q(e, ["hostname", "id"])
        },
        {
          key: "type",
          label: "Exposure",
          render: (e) => Q(e, ["exposure_type"])
        },
        {
          key: "severity",
          label: "Severity",
          render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
            tone: ["critical", "high"].includes(Q(e, ["severity"]).toLowerCase()) ? "danger" : "warn",
            children: Q(e, ["severity"])
          })
        },
        {
          key: "state",
          label: "State",
          render: (e) => Q(e, ["state"])
        },
        {
          key: "detail",
          label: "Detail",
          render: (e) => {
            let t = Q(e, ["id"], "");
            return t ? /* @__PURE__ */ (0, R.jsx)(V, {
              size: "sm",
              variant: "secondary",
              href: Mr("supply-chain-detail", t),
              children: "Open"
            }) : null;
          }
        }
      ],
      items: t.supplyChainRisks,
      emptyTitle: "No supply-chain risks recorded.",
      emptyBody: "Create a metadata-only supply-chain risk record."
    },
    remediation: {
      metricCards: [
        {
          label: "Action items",
          value: t.wafActionItems.length,
          sub: "Remediation tasks",
          icon: se,
          tone: t.wafActionItems.length > 0 ? "warn" : "success"
        },
        {
          label: "Open",
          value: t.wafActionItems.filter((e) => !os.has(Q(e, ["status"]).toLowerCase())).length,
          sub: "Not closed",
          icon: ce,
          tone: "warn"
        },
        {
          label: "Exceptions",
          value: t.wafExceptions.length,
          sub: "Approved exceptions",
          icon: j,
          tone: "info"
        }
      ],
      columns: [
        {
          key: "title",
          label: "Action item",
          render: (e) => Q(e, ["title", "id"])
        },
        {
          key: "severity",
          label: "Severity",
          render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
            tone: ["critical", "high"].includes(Q(e, ["severity"]).toLowerCase()) ? "danger" : "warn",
            children: Q(e, ["severity"])
          })
        },
        {
          key: "status",
          label: "Status",
          render: (e) => {
            let t = Q(e, ["action_item_id", "id"], "");
            return /* @__PURE__ */ (0, R.jsx)("select", {
              className: "inline-select",
              value: Q(e, ["status"], "open"),
              disabled: a !== "",
              onChange: (e) => void ve(`patch-action-${t}`, () => L(n, r, `/v1/waf/action-items/${t}`, {
                method: "PATCH",
                body: { status: e.target.value }
              }), "Action item status updated."),
              children: as.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: e,
                children: e.replace(/_/g, " ")
              }, e))
            });
          }
        },
        {
          key: "actions",
          label: "Actions",
          render: (e) => {
            let t = Q(e, ["action_item_id", "id"], "");
            return /* @__PURE__ */ (0, R.jsx)("div", {
              className: "row-actions",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                size: "sm",
                variant: "secondary",
                disabled: a !== "",
                onClick: () => g(t),
                children: "Deliver"
              })
            });
          }
        }
      ],
      items: t.wafActionItems,
      emptyTitle: "No remediation action items.",
      emptyBody: "Create action items from WAF findings."
    },
    discovery: {
      metricCards: [
        {
          label: "Entities",
          value: t.discoveryEntities.length,
          sub: "Approved entities",
          icon: ge,
          tone: "info"
        },
        {
          label: "Candidates",
          value: t.discoveryCandidates.length,
          sub: "Awaiting decision",
          icon: we,
          tone: t.discoveryCandidates.length > 0 ? "warn" : "success"
        },
        {
          label: "Inbox",
          value: t.discoveryInbox.length,
          sub: "Pending review",
          icon: se,
          tone: t.discoveryInbox.length > 0 ? "warn" : "success"
        }
      ],
      columns: [
        {
          key: "candidate",
          label: "Candidate",
          render: (e) => Q(e, [
            "value",
            "hostname",
            "entity_id",
            "id"
          ])
        },
        {
          key: "type",
          label: "Type",
          render: (e) => Q(e, [
            "entity_type",
            "candidate_type",
            "type"
          ])
        },
        {
          key: "state",
          label: "State",
          render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
            tone: Q(e, ["state"]) === "approved" ? "success" : "warn",
            children: Q(e, ["state"])
          })
        },
        {
          key: "actions",
          label: "Actions",
          render: (e) => {
            let i = Q(e, ["id", "entity_id"], ""), o = Q(e, ["state"], "");
            return /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "row-actions",
              children: [
                i ? /* @__PURE__ */ (0, R.jsx)(V, {
                  size: "sm",
                  variant: "secondary",
                  href: Mr("discovery-entity", i),
                  children: "Detail"
                }) : null,
                o === "approved" || o === "approved_target" || o === "rejected" ? null : /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
                  /* @__PURE__ */ (0, R.jsxs)("select", {
                    className: "inline-select",
                    value: y[i] ?? he,
                    disabled: a !== "" || t.targetGroups.length === 0,
                    onChange: (e) => b((t) => ({
                      ...t,
                      [i]: e.target.value
                    })),
                    "aria-label": `Approve ${Q(e, ["value", "hostname"], i)} into target group`,
                    children: [t.targetGroups.length === 0 ? /* @__PURE__ */ (0, R.jsx)("option", {
                      value: "",
                      children: "No target groups declared"
                    }) : null, t.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                      value: Q(e, ["id"]),
                      children: Q(e, ["name", "id"])
                    }, Q(e, ["id"])))]
                  }),
                  /* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "secondary",
                    disabled: a !== "" || t.targetGroups.length === 0 || !_e(i, y),
                    onClick: () => {
                      let e = _e(i, y);
                      if (!e) {
                        u("Select a target group before approving this candidate.");
                        return;
                      }
                      ve(`approve-${i}`, () => L(n, r, `/v1/discovery/candidates/${i}/approve`, {
                        method: "POST",
                        body: { target_group_id: e }
                      }), "Candidate approved.");
                    },
                    children: "Approve"
                  }),
                  /* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "ghost",
                    disabled: a !== "",
                    onClick: () => void ve(`reject-${i}`, () => L(n, r, `/v1/discovery/candidates/${i}/reject`, {
                      method: "POST",
                      body: { reason: "not_in_scope" }
                    }), "Candidate rejected."),
                    children: "Reject"
                  })
                ] }),
                o === "approved_target" && !Q(e, ["approved_target_id"], "") ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)("select", {
                  className: "inline-select",
                  value: _[i] ?? he,
                  disabled: a !== "" || t.targetGroups.length === 0,
                  onChange: (e) => v((t) => ({
                    ...t,
                    [i]: e.target.value
                  })),
                  "aria-label": `Import ${Q(e, ["value", "hostname"], i)} into target group`,
                  children: t.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                    value: Q(e, ["id"]),
                    children: Q(e, ["name", "id"])
                  }, Q(e, ["id"])))
                }), /* @__PURE__ */ (0, R.jsx)(B, {
                  size: "sm",
                  variant: "secondary",
                  disabled: a !== "" || t.targetGroups.length === 0,
                  onClick: () => void ve(`import-${i}`, () => L(n, r, `/v1/discovery/candidates/${i}/import`, {
                    method: "POST",
                    body: {
                      target_group_id: _[i] ?? he,
                      create_waf_asset: !0
                    }
                  }), "Candidate imported into declared target group."),
                  children: "Import to target group"
                })] }) : null
              ]
            });
          }
        }
      ],
      items: t.discoveryCandidates.length > 0 ? t.discoveryCandidates : t.discoveryEntities,
      emptyTitle: "No discovery records.",
      emptyBody: "Declare an entity or ingest passive discovery candidates."
    }
  }, be = ye[e] ?? ye["waf-posture"], xe = Object.fromEntries(t.targetGroups.map((e) => [Q(e, ["id"], ""), Q(e, ["name", "id"], "")])), Se = [
    {
      key: "asset",
      label: "Asset",
      render: (e) => Q(e, [
        "canonical_url",
        "display_ref",
        "hostname",
        "id"
      ])
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: Q(e, ["status", "posture_status"], "unknown") === "protected" ? "success" : "warn",
        children: Q(e, ["status", "posture_status"], "unknown")
      })
    },
    {
      key: "vendor",
      label: "Vendor",
      render: (e) => Q(e, [
        "detected_vendor",
        "expected_vendor_hint",
        "provider"
      ])
    },
    {
      key: "pass-rate",
      label: "Pass rate",
      render: (e) => {
        let n = ns(e, ["effectiveness"]);
        return qo(typeof n?.scenario_pass_rate == "number" ? n.scenario_pass_rate : Ko(Q(e, ["id"], ""), t.wafValidations));
      }
    },
    {
      key: "rule-health",
      label: "Rule health",
      render: (e) => Jo(ns(e, ["effectiveness"]))
    },
    {
      key: "target-group",
      label: "Target group",
      render: (e) => xe[Q(e, ["target_group_id"], "")] || Q(e, ["target_group_id"])
    },
    {
      key: "owner",
      label: "Owner",
      render: (e) => Q(e, ["owner_hint"])
    },
    {
      key: "detail",
      label: "Detail",
      render: (e) => {
        let t = Q(e, ["id"], "");
        return t ? /* @__PURE__ */ (0, R.jsx)(V, {
          size: "sm",
          variant: "secondary",
          href: Mr("waf-asset-detail", t),
          children: "Open"
        }) : null;
      }
    }
  ], Ce = t.wafRiskRoadmap?.tiers ?? {}, Te = Q(t.wafRiskRoadmap ?? {}, ["method"], ""), Ee = I(t.wafRiskRoadmap?.generated_at), Oe = Zo(Ce);
  function ke() {
    return Oe ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Deployment roadmap" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
      "Tiered priorities from `/v1/waf/coverage/risk-roadmap` · generated ",
      Ee,
      " · method ",
      Te || "—"
    ] })] }), /* @__PURE__ */ (0, R.jsx)(K, {
      className: "tab-panel-layout",
      children: Yo().map((e) => {
        let t = Ce[e] ?? [], n = Xo(e);
        return /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsxs)("h4", { children: [
          n.label,
          " ",
          /* @__PURE__ */ (0, R.jsxs)("span", {
            className: "muted",
            children: [
              "(",
              n.window,
              ")"
            ]
          })
        ] }), /* @__PURE__ */ (0, R.jsx)(J, {
          columns: [
            {
              key: "asset",
              label: "Asset",
              render: (e) => Q(e, [
                "hostname",
                "waf_asset_id",
                "canonical_url"
              ])
            },
            {
              key: "owner",
              label: "Owner",
              render: (e) => Q(e, ["owner_hint"])
            },
            {
              key: "risk",
              label: "Risk",
              render: (e) => Q(e, ["risk_score"])
            },
            {
              key: "status",
              label: "Status",
              render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                tone: Q(e, ["posture_status"], "unknown") === "protected" ? "success" : "warn",
                children: Q(e, ["posture_status"], "unknown")
              })
            },
            {
              key: "gap",
              label: "Primary gap",
              render: (e) => {
                let t = Array.isArray(e.primary_reason_codes) ? e.primary_reason_codes : [];
                return t.length ? t.join(", ") : "—";
              }
            },
            {
              key: "action",
              label: "Recommended action",
              render: (e) => Q(e, ["recommended_action"], "Review WAF posture gap.")
            },
            {
              key: "vendor",
              label: "Vendor",
              render: (e) => Q(e, ["detected_vendor"], "none")
            }
          ],
          items: t,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: N,
            title: `No assets in ${n.label}`,
            body: "This tier is empty for the current risk snapshot."
          })
        })] }, e);
      })
    })] }) : /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Deployment roadmap" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Tiered WAF deployment priorities from `GET /v1/waf/coverage/risk-roadmap`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(q, {
      icon: N,
      title: "Roadmap awaiting risk scores",
      body: Te ? "No roadmap items yet. Declare assets and finalize safe validations so risk scoring can rank deployment priorities." : "Risk scoring has not produced roadmap tiers yet. Finalize validations on declared assets to seed risk scores."
    }) })] });
  }
  function je(e, t) {
    !e || !t || typeof t != "object" || ie((n) => ({
      ...n,
      [e]: t
    }));
  }
  function Me(e) {
    return re[e] ?? Wo(t.wafRetests, e);
  }
  function Ne(e = 90) {
    let t = /* @__PURE__ */ new Date();
    return t.setUTCDate(t.getUTCDate() + e), t.toISOString();
  }
  function Pe() {
    return /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Drift scan" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Metadata-only posture drift comparison via `POST /v1/waf/drift-scans/run`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "product-form",
        children: [/* @__PURE__ */ (0, R.jsxs)("div", {
          className: "kv-list",
          children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Latest scan" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: te ? I(te.completed_at ?? te.created_at) : "None yet" })] }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Events opened" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Q(te ?? {}, ["events_opened"], String(ts(te ?? {}, ["drift_events_created"]))) })] })]
        }), /* @__PURE__ */ (0, R.jsx)("div", {
          className: "form-actions",
          children: /* @__PURE__ */ (0, R.jsx)(B, {
            disabled: a !== "",
            onClick: () => void ve("drift-scan-run", async () => {
              let e = await L(n, r, "/v1/waf/drift-scans/run", { method: "POST" });
              return e?.scan_result && ne(e.scan_result), e;
            }, "Drift scan completed."),
            children: "Run drift scan"
          })
        })]
      })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Drift events" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Workflow status and safe retest controls from `/v1/waf/drift-events` and `/v1/waf/retests`." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: [
          {
            key: "type",
            label: "Drift type",
            render: (e) => Q(e, [
              "drift_type",
              "reason_code",
              "type"
            ])
          },
          {
            key: "asset",
            label: "Asset",
            render: (e) => Q(e, [
              "waf_asset_id",
              "canonical_url",
              "hostname"
            ])
          },
          {
            key: "severity",
            label: "Severity",
            render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
              tone: ["critical", "high"].includes(Q(e, ["severity"]).toLowerCase()) ? "danger" : "warn",
              children: Q(e, ["severity"])
            })
          },
          {
            key: "seen",
            label: "First seen",
            render: (e) => I(e.first_seen_at ?? e.created_at)
          },
          {
            key: "status",
            label: "Status",
            render: (e) => {
              let t = Q(e, ["id"], "");
              return /* @__PURE__ */ (0, R.jsx)("select", {
                className: "inline-select",
                value: Q(e, ["status"], "open"),
                disabled: a !== "",
                onChange: (e) => void ve(`patch-drift-${t}`, () => L(n, r, `/v1/waf/drift-events/${t}`, {
                  method: "PATCH",
                  body: { status: e.target.value }
                }), "Drift status updated."),
                children: Ho.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                  value: e,
                  children: e.replace(/_/g, " ")
                }, e))
              });
            }
          },
          {
            key: "retest",
            label: "Retest",
            render: (e) => {
              let t = Q(e, ["id"], ""), i = Me(t), o = Q(i, ["id"], ""), s = Q(i, ["status"], "none");
              return /* @__PURE__ */ (0, R.jsxs)("div", {
                className: "stack-tight",
                children: [/* @__PURE__ */ (0, R.jsx)("span", {
                  className: "muted small",
                  children: o ? `${o} · ${s}` : "No retest yet"
                }), /* @__PURE__ */ (0, R.jsxs)("div", {
                  className: "row-actions",
                  children: [/* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "secondary",
                    disabled: a !== "",
                    onClick: () => void ve(`drift-retest-${t}`, async () => {
                      let e = await L(n, r, `/v1/waf/drift-events/${t}/retest`, {
                        method: "POST",
                        body: {}
                      });
                      return je(t, e?.retest_request), e;
                    }, "Retest requested."),
                    children: "Request"
                  }), o ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "ghost",
                    disabled: a !== "",
                    onClick: () => void ve(`retest-exec-${o}`, async () => {
                      let e = await L(n, r, `/v1/waf/retests/${o}/execute`, {
                        method: "POST",
                        body: {}
                      });
                      return je(t, e?.retest_request ?? i), e;
                    }, "Retest execution delegated."),
                    children: "Execute"
                  }), /* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "ghost",
                    disabled: a !== "",
                    onClick: () => void ve(`retest-complete-${o}`, async () => {
                      let e = await L(n, r, `/v1/waf/retests/${o}/complete`, { method: "POST" });
                      return je(t, e?.retest_request ?? i), e;
                    }, "Retest completed from verdict evidence."),
                    children: "Complete"
                  })] }) : null]
                })]
              });
            }
          }
        ],
        items: t.wafDriftEvents,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: Ae,
          title: "No drift events.",
          body: "Drift events appear after posture weakens or drift scans detect changes."
        })
      }) })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Validation plans (operator)" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Safe orchestrator plans from `/v1/waf/validation-plans`; production scheduling still uses external runner." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "stack",
        children: [/* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: (e) => {
            e.preventDefault();
            let t = e.currentTarget, i = new FormData(t), a = String(i.get("target_group_id") ?? he).trim();
            if (!a) {
              u("Select a target group before creating a validation plan.");
              return;
            }
            let o = Uo.filter((e) => i.get(`scenario_${e}`) === "on");
            ve("create-validation-plan", () => L(n, r, "/v1/waf/validation-plans", {
              method: "POST",
              body: {
                target_group_id: a,
                mode: String(i.get("mode") ?? "manual").trim(),
                scenarios: o.length > 0 ? o : ["marker", "fingerprint"],
                max_concurrent: Number(i.get("max_concurrent") ?? 2)
              }
            }), "Validation plan created."), t.reset();
          },
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsx)("select", {
              name: "target_group_id",
              defaultValue: he,
              required: !0,
              children: t.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: Q(e, ["id"]),
                children: Q(e, ["name", "id"])
              }, Q(e, ["id"])))
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Mode" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "mode",
              defaultValue: "manual",
              children: [/* @__PURE__ */ (0, R.jsx)("option", {
                value: "manual",
                children: "manual"
              }), /* @__PURE__ */ (0, R.jsx)("option", {
                value: "on_demand",
                children: "on_demand"
              })]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Max concurrent" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "max_concurrent",
              type: "number",
              min: "1",
              max: "10",
              defaultValue: "2"
            })] }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "check-row full",
              children: Uo.map((e) => /* @__PURE__ */ (0, R.jsxs)("label", {
                className: "check-row",
                children: [/* @__PURE__ */ (0, R.jsx)("input", {
                  name: `scenario_${e}`,
                  type: "checkbox",
                  defaultChecked: e === "marker" || e === "fingerprint"
                }), /* @__PURE__ */ (0, R.jsx)("span", { children: e })]
              }, e))
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: a !== "" || t.targetGroups.length === 0,
                children: "Create plan"
              })
            })
          ]
        }), /* @__PURE__ */ (0, R.jsx)(J, {
          columns: [
            {
              key: "id",
              label: "Plan",
              render: (e) => Q(e, ["id"])
            },
            {
              key: "target",
              label: "Target group",
              render: (e) => Q(e, ["target_group_id"])
            },
            {
              key: "state",
              label: "State",
              render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
                tone: Q(e, ["state"]) === "completed" ? "success" : "warn",
                children: Q(e, ["state"])
              })
            },
            {
              key: "scenarios",
              label: "Scenarios",
              render: (e) => Array.isArray(e.scenarios) ? e.scenarios.join(", ") : "—"
            },
            {
              key: "actions",
              label: "Actions",
              render: (e) => {
                let t = Q(e, ["id"], ""), i = Q(e, ["state"], "");
                return /* @__PURE__ */ (0, R.jsxs)("div", {
                  className: "row-actions",
                  children: [["completed", "cancelled"].includes(i) ? null : /* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "secondary",
                    disabled: a !== "",
                    onClick: () => void ve(`plan-exec-${t}`, () => L(n, r, `/v1/waf/validation-plans/${t}/execute`, { method: "POST" }), "Validation plan execute tick completed."),
                    children: "Execute"
                  }), ["completed", "cancelled"].includes(i) ? null : /* @__PURE__ */ (0, R.jsx)(B, {
                    size: "sm",
                    variant: "ghost",
                    disabled: a !== "",
                    onClick: () => void ve(`plan-cancel-${t}`, () => L(n, r, `/v1/waf/validation-plans/${t}/cancel`, { method: "POST" }), "Validation plan cancelled."),
                    children: "Cancel"
                  })]
                });
              }
            }
          ],
          items: t.wafValidationPlans,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: pe,
            title: "No validation plans.",
            body: "Create a safe validation plan for a declared target group."
          })
        })]
      })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Approved exceptions" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Tenant-scoped metadata-only exceptions from `GET /v1/waf/exceptions` and `POST /v1/waf/assets/:id/exception`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "stack",
        children: [/* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: (e) => {
            e.preventDefault();
            let t = e.currentTarget, i = new FormData(t), a = String(i.get("waf_asset_id") ?? ae).trim();
            if (!a) {
              u("Select a WAF asset before creating an exception.");
              return;
            }
            ve("create-waf-exception", () => L(n, r, `/v1/waf/assets/${encodeURIComponent(a)}/exception`, {
              method: "POST",
              body: {
                owner: String(i.get("owner") ?? "edge-team").trim(),
                reason: String(i.get("reason") ?? "approved_scope_exception").trim(),
                expires_at: Ne()
              }
            }), "WAF exception recorded."), t.reset();
          },
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "WAF asset" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              name: "waf_asset_id",
              value: ae,
              onChange: (e) => oe(e.target.value),
              required: !0,
              children: [t.wafAssets.length === 0 ? /* @__PURE__ */ (0, R.jsx)("option", {
                value: "",
                children: "No assets declared"
              }) : null, t.wafAssets.map((e) => {
                let t = Q(e, ["id"], "");
                return /* @__PURE__ */ (0, R.jsx)("option", {
                  value: t,
                  children: Q(e, [
                    "canonical_url",
                    "display_ref",
                    "id"
                  ])
                }, t);
              })]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Owner" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "owner",
              defaultValue: "edge-team",
              required: !0
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Reason" }), /* @__PURE__ */ (0, R.jsx)("input", {
                name: "reason",
                defaultValue: "approved_scope_exception",
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: a !== "" || t.wafAssets.length === 0,
                children: "Create exception"
              })
            })
          ]
        }), /* @__PURE__ */ (0, R.jsx)(J, {
          columns: [
            {
              key: "asset",
              label: "Asset",
              render: (e) => Q(e, ["waf_asset_id", "asset_id"])
            },
            {
              key: "owner",
              label: "Owner",
              render: (e) => Q(e, ["owner"])
            },
            {
              key: "reason",
              label: "Reason",
              render: (e) => Q(e, ["reason"])
            },
            {
              key: "expires",
              label: "Expires",
              render: (e) => I(e.expires_at)
            }
          ],
          items: t.wafExceptions,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No active exceptions.",
            body: "Approved exceptions appear here after asset-scoped exception creation."
          })
        })]
      })] })
    ] });
  }
  function Fe() {
    return e === "waf-posture" ? /* @__PURE__ */ (0, R.jsxs)("form", {
      className: "product-form",
      onSubmit: (e) => {
        e.preventDefault();
        let t = e.currentTarget, i = new FormData(t), a = String(i.get("target_group_id") ?? x).trim(), o = String(i.get("target_id") ?? "").trim();
        if (!a) {
          u("Select a declared target group before creating a WAF asset.");
          return;
        }
        if (!o) {
          u("Select a target from the chosen group before creating a WAF asset.");
          return;
        }
        ve("create-waf-asset", () => L(n, r, "/v1/waf/assets", {
          method: "POST",
          body: {
            target_group_id: a,
            target_id: o,
            canonical_url: String(i.get("canonical_url") ?? "").trim(),
            owner_hint: String(i.get("owner_hint") ?? "edge-team").trim()
          }
        }), "WAF asset created."), t.reset();
      },
      children: [
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target group" }), /* @__PURE__ */ (0, R.jsxs)("select", {
          name: "target_group_id",
          value: x,
          disabled: t.targetGroups.length === 0,
          onChange: (e) => S(e.target.value),
          children: [t.targetGroups.length === 0 ? /* @__PURE__ */ (0, R.jsx)("option", {
            value: "",
            children: "No target groups declared"
          }) : null, t.targetGroups.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
            value: Q(e, ["id"]),
            children: Q(e, ["name", "id"])
          }, Q(e, ["id"])))]
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Target" }), /* @__PURE__ */ (0, R.jsxs)("select", {
          name: "target_id",
          defaultValue: "",
          disabled: E || w.length === 0,
          required: !0,
          children: [/* @__PURE__ */ (0, R.jsx)("option", {
            value: "",
            children: E ? "Loading targets…" : w.length === 0 ? "Add a target to the selected group" : "Select target"
          }), w.map((e) => {
            let t = Q(e, ["id"], "");
            return /* @__PURE__ */ (0, R.jsxs)("option", {
              value: t,
              children: [
                Q(e, ["value", "id"]),
                " (",
                Q(e, ["kind"], "target"),
                ")"
              ]
            }, t);
          })]
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Canonical URL" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "canonical_url",
          placeholder: "https://app.example.com",
          required: !0
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Owner hint" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "owner_hint",
          defaultValue: "edge-team"
        })] }),
        /* @__PURE__ */ (0, R.jsx)("div", {
          className: "form-actions full",
          children: /* @__PURE__ */ (0, R.jsx)(B, {
            type: "submit",
            disabled: a !== "" || t.targetGroups.length === 0 || w.length === 0,
            children: "Create WAF asset"
          })
        })
      ]
    }) : e === "cve-pipeline" ? /* @__PURE__ */ (0, R.jsxs)("form", {
      className: "product-form",
      onSubmit: (e) => {
        e.preventDefault();
        let t = e.currentTarget, i = new FormData(t);
        ve("create-cve", () => L(n, r, "/v1/waf/cve-pipeline", {
          method: "POST",
          body: {
            cve_id: String(i.get("cve_id") ?? "").trim(),
            severity: String(i.get("severity") ?? "high").trim(),
            affected_products: String(i.get("affected_products") ?? "declared-service").trim().split(",").map((e) => e.trim()).filter(Boolean),
            known_exploited: i.get("known_exploited") === "on"
          }
        }), "CVE pipeline item created."), t.reset();
      },
      children: [
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "CVE ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "cve_id",
          placeholder: "CVE-2026-0001",
          required: !0
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Affected products" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "affected_products",
          defaultValue: "declared-service",
          required: !0
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Severity" }), /* @__PURE__ */ (0, R.jsxs)("select", {
          name: "severity",
          defaultValue: "high",
          children: [
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "critical",
              children: "critical"
            }),
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "high",
              children: "high"
            }),
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "medium",
              children: "medium"
            })
          ]
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", {
          className: "check-row full",
          children: [/* @__PURE__ */ (0, R.jsx)("input", {
            name: "known_exploited",
            type: "checkbox"
          }), /* @__PURE__ */ (0, R.jsx)("span", { children: "Known exploited (KEV)" })]
        }),
        /* @__PURE__ */ (0, R.jsx)("div", {
          className: "form-actions full",
          children: /* @__PURE__ */ (0, R.jsx)(B, {
            type: "submit",
            disabled: a !== "",
            children: "Create CVE item"
          })
        })
      ]
    }) : e === "supply-chain" ? /* @__PURE__ */ (0, R.jsxs)("form", {
      className: "product-form",
      onSubmit: (e) => {
        e.preventDefault();
        let t = e.currentTarget, i = new FormData(t);
        ve("create-risk", () => L(n, r, "/v1/waf/supply-chain/risks", {
          method: "POST",
          body: {
            exposure_type: String(i.get("exposure_type") ?? "dangling_cname").trim(),
            hostname: String(i.get("hostname") ?? "").trim(),
            severity: String(i.get("severity") ?? "high").trim(),
            confidence: Number(i.get("confidence") ?? .8),
            state: "suspected",
            evidence_summary: { data_source: "customer_declared" },
            remediation_steps: ["Review DNS chain and remove dangling reference."]
          }
        }), "Supply-chain risk created."), t.reset();
      },
      children: [
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Hostname" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "hostname",
          placeholder: "orphan.example.com",
          required: !0
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Exposure type" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "exposure_type",
          defaultValue: "dangling_cname"
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Severity" }), /* @__PURE__ */ (0, R.jsxs)("select", {
          name: "severity",
          defaultValue: "high",
          children: [/* @__PURE__ */ (0, R.jsx)("option", {
            value: "critical",
            children: "critical"
          }), /* @__PURE__ */ (0, R.jsx)("option", {
            value: "high",
            children: "high"
          })]
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Confidence" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "confidence",
          type: "number",
          min: "0",
          max: "1",
          step: "0.1",
          defaultValue: "0.8"
        })] }),
        /* @__PURE__ */ (0, R.jsx)("div", {
          className: "form-actions full",
          children: /* @__PURE__ */ (0, R.jsx)(B, {
            type: "submit",
            disabled: a !== "",
            children: "Create risk"
          })
        })
      ]
    }) : e === "remediation" ? /* @__PURE__ */ (0, R.jsxs)("form", {
      className: "product-form",
      onSubmit: (e) => {
        e.preventDefault();
        let t = e.currentTarget, i = new FormData(t), a = String(i.get("finding_id") ?? "").trim();
        if (!a) {
          u("Select a finding before creating an action item.");
          return;
        }
        ve("create-action-item", () => L(n, r, "/v1/waf/action-items", {
          method: "POST",
          body: { finding_id: a }
        }), "Remediation action item created."), t.reset();
      },
      children: [/* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Finding" }), /* @__PURE__ */ (0, R.jsxs)("select", {
        name: "finding_id",
        defaultValue: me,
        required: !0,
        children: [t.findings.length === 0 ? /* @__PURE__ */ (0, R.jsx)("option", {
          value: "",
          children: "No findings available"
        }) : null, t.findings.map((e) => {
          let t = Q(e, ["id"], "");
          return /* @__PURE__ */ (0, R.jsxs)("option", {
            value: t,
            children: [
              Q(e, ["title", "id"]),
              " (",
              Q(e, ["severity"]),
              ")"
            ]
          }, t);
        })]
      })] }), /* @__PURE__ */ (0, R.jsx)("div", {
        className: "form-actions full",
        children: /* @__PURE__ */ (0, R.jsx)(B, {
          type: "submit",
          disabled: a !== "" || t.findings.length === 0,
          children: "Create action item"
        })
      })]
    }) : e === "discovery" ? /* @__PURE__ */ (0, R.jsxs)("form", {
      className: "product-form",
      onSubmit: (e) => {
        e.preventDefault();
        let t = e.currentTarget, i = new FormData(t), a = String(i.get("root_domain") ?? "").trim().toLowerCase(), o = String(i.get("display_name") ?? "").trim(), s = String(i.get("entity_id") ?? "").trim() || `ent_${a.replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "") || "declared"}`;
        if (!a) {
          u("Enter a root domain before declaring an entity.");
          return;
        }
        ve("create-entity", () => L(n, r, "/v1/discovery/entities", {
          method: "POST",
          body: {
            entity_id: s,
            entity_type: String(i.get("entity_type") ?? "parent_organization").trim(),
            name: o || a,
            display_name: o || a,
            root_domains: [a],
            country: String(i.get("country") ?? "US").trim(),
            confidence: Number(i.get("confidence") ?? .85),
            source: String(i.get("source") ?? "customer_import").trim()
          }
        }), "Discovery entity declared."), t.reset();
      },
      children: [
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Entity ID" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "entity_id",
          placeholder: "ent_acme (optional)"
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Type" }), /* @__PURE__ */ (0, R.jsxs)("select", {
          name: "entity_type",
          defaultValue: "parent_organization",
          children: [
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "parent_organization",
              children: "parent organization"
            }),
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "subsidiary",
              children: "subsidiary"
            }),
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "brand",
              children: "brand"
            }),
            /* @__PURE__ */ (0, R.jsx)("option", {
              value: "region",
              children: "region"
            })
          ]
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Display name" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "display_name",
          placeholder: "Acme Corp"
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Root domain" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "root_domain",
          placeholder: "example.com",
          required: !0
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Country" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "country",
          defaultValue: "US"
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Confidence" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "confidence",
          type: "number",
          min: "0",
          max: "1",
          step: "0.05",
          defaultValue: "0.85"
        })] }),
        /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Source" }), /* @__PURE__ */ (0, R.jsx)("input", {
          name: "source",
          defaultValue: "customer_import"
        })] }),
        /* @__PURE__ */ (0, R.jsx)("div", {
          className: "form-actions full",
          children: /* @__PURE__ */ (0, R.jsx)(B, {
            type: "submit",
            disabled: a !== "",
            children: "Declare entity"
          })
        })
      ]
    }) : null;
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: e }),
      M ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
        (s || l) && /* @__PURE__ */ (0, R.jsx)("div", {
          className: l ? "form-banner error" : "form-banner",
          children: l || s
        }),
        /* @__PURE__ */ (0, R.jsx)("div", {
          className: "metric-grid three",
          children: be.metricCards.map((e) => /* @__PURE__ */ (0, R.jsx)(X, { ...e }, e.label))
        }),
        e === "waf-posture" ? /* @__PURE__ */ (0, R.jsx)(Ar, {
          value: O,
          options: Vo.map((e) => ({
            id: e.id,
            label: e.label
          })),
          onChange: ee,
          className: "tabs-wrap"
        }) : null,
        e !== "waf-posture" || O === "overview" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: e === "remediation" ? "Create action item" : "Create record" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Route-specific create action backed by live backend APIs." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: Fe() })] }) : null,
        e === "remediation" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Connector delivery preview" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Safe dry-run delivery through `POST /v1/waf/action-items/:id/deliver` with channel and connector fields." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "product-form",
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Action item" }), /* @__PURE__ */ (0, R.jsxs)("select", {
              value: h || Q(t.wafActionItems[0] ?? {}, ["action_item_id", "id"], ""),
              onChange: (e) => g(e.target.value),
              children: [/* @__PURE__ */ (0, R.jsx)("option", {
                value: "",
                children: "Select action item"
              }), t.wafActionItems.map((e) => {
                let t = Q(e, ["action_item_id", "id"], "");
                return /* @__PURE__ */ (0, R.jsx)("option", {
                  value: t,
                  children: Q(e, ["title", "id"])
                }, t);
              })]
            })] }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Channel / connector" }), /* @__PURE__ */ (0, R.jsx)("select", {
              value: p,
              onChange: (e) => m(e.target.value),
              children: ss.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
                value: e,
                children: e
              }, e))
            })] }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                disabled: a !== "" || t.wafActionItems.length === 0,
                onClick: () => {
                  let e = h || Q(t.wafActionItems[0] ?? {}, ["action_item_id", "id"], "");
                  if (!e) {
                    u("Select an action item before delivering.");
                    return;
                  }
                  ve(`deliver-${e}`, () => L(n, r, `/v1/waf/action-items/${e}/deliver`, {
                    method: "POST",
                    body: {
                      channel: p,
                      connector: p,
                      dry_run: !0
                    }
                  }), "Dry-run deliver preview generated.");
                },
                children: "Dry-run deliver"
              })
            })
          ]
        })] }) : null,
        e === "waf-posture" && O === "overview" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Coverage summary" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "From `/v1/waf/coverage`." })] }), /* @__PURE__ */ (0, R.jsx)(K, {
          className: "factor-list",
          children: [
            "protected",
            "underprotected",
            "unprotected",
            "unknown",
            "excluded"
          ].map((e) => {
            let n = ts(t.wafCoverage ?? {}, [e]), r = rs(t.wafCoverage, ["percentages", e], 0);
            return /* @__PURE__ */ (0, R.jsxs)("div", {
              className: "factor",
              children: [
                /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("strong", { children: e }), /* @__PURE__ */ (0, R.jsxs)("span", { children: [n, " assets"] })] }),
                /* @__PURE__ */ (0, R.jsxs)(z, {
                  tone: e === "protected" ? hn(r) : n > 0 ? "warn" : "muted",
                  children: [Math.round(r), "%"]
                }),
                /* @__PURE__ */ (0, R.jsx)(Or, { value: r })
              ]
            }, e);
          })
        })] }) : null,
        e === "waf-posture" && O === "overview" ? Pe() : null,
        e === "waf-posture" && O === "roadmap" ? ke() : null,
        e === "waf-posture" && O === "assets" ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Declared assets" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Per-asset pass rate uses finalized validations in the last 30 days. Rule health appears when connector snapshots are available." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: Se,
          items: t.wafAssets,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: N,
            title: "No WAF assets recorded.",
            body: "Create a declared WAF asset or import from an approved connector snapshot."
          })
        }) })] }) : null,
        e === "waf-posture" ? null : /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: Wn.get(e)?.label }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Live API records with triage actions." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: be.columns,
          items: be.items,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: N,
            title: be.emptyTitle,
            body: be.emptyBody
          })
        }) })] }),
        d ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsx)(U, { children: /* @__PURE__ */ (0, R.jsx)(W, { children: "Action result" }) }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)("pre", {
          className: "codeblock",
          children: d
        }) })] }) : null
      ] }) : /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: ue ? "WAF posture disabled" : "External discovery disabled" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Optional add-ons fail closed when their feature flag is off." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(q, {
        icon: N,
        title: ue ? "Enable ASTRANULL_WAF_POSTURE_ENABLED=1" : "Enable ASTRANULL_EXTERNAL_DISCOVERY_ENABLED=1",
        body: "No posture data is invented while the backend route family is disabled."
      }) })] }),
      /* @__PURE__ */ (0, R.jsx)(aa, {})
    ]
  });
}
//#endregion
//#region apps/web/react/src/lib/release-evidence.ts
var fs = /* @__PURE__ */ "third_party_security_review.migration_apply.operator_runbook_exercise.oidc_prod_auth_preflight.edge_protection.agent_sbom_provenance.agent_install_matrix.agent_mtls_gateway.agent_trust_key_ceremony.governed_adapter.provider_approval.kill_switch_drill.postgres_concurrency.dr_restore.ui_accessibility_matrix.notification_provider_config.probe_fleet_matrix.vector_safety_policy.secret_rotation_drill.observability_slo.support_readiness.evidence_snapshot_manifest.postgres_tenant_query_audit.rollback_fixforward.kms_vault_posture.control_plane_container_release.staging_e2e_matrix.compliance_legal_signoff.authorization_custody.placement_confidence_staging.gateway_load_abuse".split(".");
function ps(e) {
  let t = typeof e == "string" ? e.trim().toLowerCase() : "accepted";
  return t === "accepted" || t === "approved";
}
function ms(e = {}) {
  return e.dry_run === !0 || e.submittable === !1 || e.collector_dry_run === !0 ? !1 : ps(e.status);
}
function hs(e = []) {
  let t = /* @__PURE__ */ new Set();
  for (let n of e) {
    let e = typeof n.kind == "string" ? n.kind : "";
    !e || !ms(n) || t.add(e);
  }
  let n = fs.filter((e) => !t.has(e));
  return {
    expected: fs.length,
    recorded: t.size,
    missing: [...n],
    kindsComplete: n.length === 0 && t.size > 0
  };
}
function gs(e) {
  if (!e || typeof e != "object") return null;
  for (let t of [
    "evidence_uri",
    "review_report_uri",
    "remediation_tracker_uri",
    "runner_evidence_uri",
    "post_apply_check_uri",
    "signoff_reference"
  ]) {
    let n = e[t];
    if (typeof n == "string" && n.trim()) return n.trim();
  }
  for (let [t, n] of Object.entries(e)) {
    if (typeof n != "string" || !n.trim()) continue;
    let e = t.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();
    if (e.endsWith("_uri") || e.endsWith("_reference")) return n.trim();
  }
  return null;
}
function _s(e) {
  if (!e) return "No validation summary";
  if (e.ok === !0) return "Contract valid (metadata-only)";
  let t = [], n = Array.isArray(e.missing_fields) ? e.missing_fields : [], r = Array.isArray(e.forbidden_fields) ? e.forbidden_fields : [];
  return n.length && t.push(`missing ${n.length} field(s)`), r.length && t.push(`forbidden ${r.length} field(s)`), t.length ? `Invalid — ${t.join("; ")}` : "Invalid";
}
//#endregion
//#region apps/web/react/src/pages/governance-pages.tsx
function $(e, t, n = "—") {
  if (!e) return n;
  for (let n of t) {
    let t = e[n];
    if (t != null && t !== "") return String(t);
  }
  return n;
}
function vs(e, t) {
  let n = e;
  for (let e of t) {
    if (!n || typeof n != "object" || Array.isArray(n)) return null;
    n = n[e];
  }
  return n && typeof n == "object" && !Array.isArray(n) ? n : null;
}
function ys(e, t, n = "—") {
  let r = e;
  for (let e of t) {
    if (!r || typeof r != "object" || Array.isArray(r)) return n;
    r = r[e];
  }
  return r != null && r !== "" ? String(r) : n;
}
var bs = [
  "finding.high_severity",
  "agent.offline",
  "safe_test.completed",
  "high_scale.state_change",
  "report.ready",
  "bootstrap_token.created",
  "bootstrap_token.revoked"
];
function xs(e) {
  return e === "admin" || e === "owner";
}
function Ss(e) {
  return [
    "admin",
    "owner",
    "soc",
    "auditor"
  ].includes(String(e ?? ""));
}
function Cs(e) {
  return [
    "admin",
    "owner",
    "soc",
    "auditor"
  ].includes(String(e ?? ""));
}
function ws(e) {
  return e.flatMap((e) => (Array.isArray(e.delivery_attempts) ? e.delivery_attempts : []).map((t) => ({
    ...t,
    event_id: e.id,
    trigger: e.trigger
  })));
}
function Ts({ data: e, config: t, session: n, onRefresh: r }) {
  let [i, a] = (0, C.useState)(""), [o, s] = (0, C.useState)(""), [c, l] = (0, C.useState)(""), u = xs(n.role), d = (0, C.useMemo)(() => ws(e.notificationEvents), [e.notificationEvents]), f = d.filter((e) => $(e, ["status"]) === "provider_retry_scheduled"), p = d.filter((e) => $(e, ["status"]) === "provider_failed_dlq"), m = [
    {
      key: "channel",
      label: "Channel",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: $(e, ["channel"])
      })
    },
    {
      key: "enabled",
      label: "Enabled",
      render: (e) => e.enabled === !1 ? "disabled" : "enabled"
    },
    {
      key: "triggers",
      label: "Triggers",
      render: (e) => Array.isArray(e.triggers) ? e.triggers.length : 0
    },
    {
      key: "destination",
      label: "Destination",
      render: (e) => $(e, ["destination_preview"], "metadata-only")
    }
  ], h = [
    {
      key: "trigger",
      label: "Trigger",
      render: (e) => $(e, ["trigger"])
    },
    {
      key: "subject",
      label: "Subject",
      render: (e) => $(e, ["subject"])
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    }
  ];
  async function g(e, t, n) {
    a(e), l(""), s("");
    try {
      let e = await t();
      return s(n), await r(), e;
    } catch (e) {
      let t = e.payload;
      return l(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Notification action failed.")), null;
    } finally {
      a("");
    }
  }
  function _(e, t) {
    let n = t.trim();
    return e === "webhook" ? /^https?:\/\//i.test(n) ? n : "https://hooks.example.invalid/notifications" : e === "email" ? n.includes("@") ? n : "alerts@example.invalid" : n || `${e}-destination.example.invalid`;
  }
  async function v(e) {
    e.preventDefault();
    let r = e.currentTarget, i = new FormData(r), a = String(i.get("channel") ?? "webhook").trim(), o = String(i.get("trigger") ?? "finding.high_severity").trim(), s = _(a, String(i.get("destination_preview") ?? "").trim());
    await g("create-notification-rule", () => L(t, n, "/v1/notifications", {
      method: "POST",
      body: {
        channel: a,
        enabled: !0,
        triggers: [o],
        destination: s
      }
    }), "Notification rule created (metadata-only delivery ledger)."), r.reset();
  }
  async function y(e) {
    await g(`process-retries-${e ? "preview" : "run"}`, () => L(t, n, "/v1/notifications/retries/process", {
      method: "POST",
      body: { dry_run: e }
    }), e ? "Due retry preview completed." : "Due retries processed (metadata-only).");
  }
  async function b(e) {
    let r = p.map((e) => $(e, ["id", "attempt_id"], "")).filter(Boolean);
    await g(`redrive-dlq-${e ? "preview" : "run"}`, () => L(t, n, "/v1/notifications/dlq/redrive", {
      method: "POST",
      body: {
        dry_run: e,
        attempt_ids: r.length > 0 ? r : void 0
      }
    }), e ? "DLQ redrive preview completed." : "DLQ attempts requeued (metadata-only).");
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, { route: "notifications" }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Rules",
            value: e.notificationRules.length,
            sub: "Tenant notification rules",
            icon: te,
            tone: "info"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Events",
            value: e.notificationEvents.length,
            sub: "Recent emitted events",
            icon: se,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "DLQ",
            value: p.length,
            sub: `${f.length} retry scheduled`,
            icon: De,
            tone: p.length > 0 ? "warn" : "success"
          })
        ]
      }),
      (o || c) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: c ? "form-banner error" : "form-banner",
        children: c || o
      }),
      u ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Create notification rule" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Metadata-only rule creation. External delivery remains opt-in through server delivery mode." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
        className: "product-form",
        onSubmit: v,
        children: [
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Channel" }), /* @__PURE__ */ (0, R.jsxs)("select", {
            name: "channel",
            defaultValue: "webhook",
            children: [
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "webhook",
                children: "webhook"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "email",
                children: "email"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "slack",
                children: "slack"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "teams",
                children: "teams"
              }),
              /* @__PURE__ */ (0, R.jsx)("option", {
                value: "in_app",
                children: "in_app"
              })
            ]
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Trigger" }), /* @__PURE__ */ (0, R.jsx)("select", {
            name: "trigger",
            defaultValue: "finding.high_severity",
            children: bs.map((e) => /* @__PURE__ */ (0, R.jsx)("option", {
              value: e,
              children: e
            }, e))
          })] }),
          /* @__PURE__ */ (0, R.jsxs)("label", {
            className: "full",
            children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Destination" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "destination_preview",
              placeholder: "https://hooks.example.invalid/notifications"
            })]
          }),
          /* @__PURE__ */ (0, R.jsx)("div", {
            className: "form-actions full",
            children: /* @__PURE__ */ (0, R.jsx)(B, {
              type: "submit",
              disabled: i !== "",
              children: "Add rule"
            })
          })
        ]
      }) })] }) : /* @__PURE__ */ (0, R.jsx)(H, { children: /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)("p", {
        className: "muted",
        children: "Notification write access requires owner or admin role."
      }) }) }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsx)(U, { children: /* @__PURE__ */ (0, R.jsx)(W, { children: "Rules" }) }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: m,
          items: e.notificationRules,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: te,
            title: "No notification rules.",
            body: "Create a metadata-only rule to start recording delivery intent."
          })
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsx)(U, { children: /* @__PURE__ */ (0, R.jsx)(W, { children: "Recent events" }) }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: h,
          items: e.notificationEvents.slice().reverse(),
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: se,
            title: "No notification events.",
            body: "Events appear after configured triggers fire."
          })
        }) })] })]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Delivery operations" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Retry and DLQ controls are metadata-only in developer validation." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "row-actions",
        children: [
          /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            disabled: !u || i !== "",
            onClick: () => void y(!0),
            children: "Preview due retries"
          }),
          /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            disabled: !u || i !== "",
            onClick: () => void y(!1),
            children: "Process due retries"
          }),
          /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "ghost",
            disabled: !u || i !== "" || p.length === 0,
            onClick: () => void b(!0),
            children: "Preview DLQ redrive"
          }),
          /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            disabled: !u || i !== "" || p.length === 0,
            onClick: () => void b(!1),
            children: "Redrive DLQ"
          })
        ]
      })] })
    ]
  });
}
function Es({ data: e, session: t }) {
  let [n, r] = (0, C.useState)(""), [i, a] = (0, C.useState)(!1), [o, s] = (0, C.useState)(""), c = Ss(t.role), l = e.audit.filter((e) => {
    let t = $(e, ["action"], "").toLowerCase();
    return i && !t.includes("custody") && !t.includes("export") && !t.includes("report") ? !1 : n.trim() ? `${$(e, ["action"])} ${$(e, ["resource_type"])} ${$(e, ["resource_id"])}`.toLowerCase().includes(n.trim().toLowerCase()) : !0;
  }), u = l.find((e) => $(e, ["id", "audit_id"], "") === o) ?? null;
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, { route: "audit" }), c ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Audit log" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Security-relevant tenant actions with hash-chain integrity on the backend." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [/* @__PURE__ */ (0, R.jsxs)("div", {
      className: "product-form",
      children: [/* @__PURE__ */ (0, R.jsxs)("label", {
        className: "full",
        children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Filter" }), /* @__PURE__ */ (0, R.jsx)("input", {
          value: n,
          onChange: (e) => r(e.target.value),
          placeholder: "action, resource type, or id"
        })]
      }), /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Custody chain only" }), /* @__PURE__ */ (0, R.jsx)("input", {
        type: "checkbox",
        checked: i,
        onChange: (e) => a(e.target.checked)
      })] })]
    }), /* @__PURE__ */ (0, R.jsx)(J, {
      columns: [
        {
          key: "time",
          label: "Time",
          render: (e) => I(e.timestamp ?? e.created_at)
        },
        {
          key: "action",
          label: "Action",
          render: (e) => $(e, ["action"])
        },
        {
          key: "resource",
          label: "Resource",
          render: (e) => `${$(e, ["resource_type"], "")} ${$(e, ["resource_id"], "")}`.trim()
        },
        {
          key: "actor",
          label: "Actor",
          render: (e) => $(e, ["actor_role", "actor_user_id"], "system")
        },
        {
          key: "inspect",
          label: "Inspect",
          render: (e) => {
            let t = $(e, ["id", "audit_id"], $(e, ["created_at"], ""));
            return /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: t === o ? "default" : "secondary",
              onClick: () => s(t),
              children: "Open"
            });
          }
        }
      ],
      items: l.slice().reverse(),
      empty: /* @__PURE__ */ (0, R.jsx)(q, {
        icon: se,
        title: "No audit entries.",
        body: "Security-relevant actions will appear here after workflow activity."
      })
    })] })] }), u ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Custody and metadata drilldown" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
      $(u, ["action"]),
      " · ",
      $(u, ["resource_type"])
    ] })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
      className: "kv-list",
      children: [
        /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Actor" }), /* @__PURE__ */ (0, R.jsxs)("strong", { children: [
          $(u, ["actor_user_id"]),
          " (",
          $(u, ["actor_role"]),
          ")"
        ] })] }),
        /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Resource" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: $(u, ["resource_id"]) })] }),
        /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Timestamp" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(u.timestamp ?? u.created_at) })] }),
        /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Metadata keys" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: Object.keys(u.metadata ?? {}).join(", ") || "none" })] }),
        u.metadata && typeof u.metadata == "object" ? /* @__PURE__ */ (0, R.jsx)("pre", {
          className: "codeblock",
          children: JSON.stringify(u.metadata, null, 2).slice(0, 1800)
        }) : null
      ]
    })] }) : null] }) : /* @__PURE__ */ (0, R.jsx)(q, {
      icon: se,
      title: "Audit access required.",
      body: "Switch to owner, admin, SOC, or auditor role to read the tenant audit log."
    })]
  });
}
function Ds({ data: e, session: t }) {
  let n = Cs(t.role), r = e.releaseAttestation, i = hs(e.releaseEvidence), a = [
    {
      key: "kind",
      label: "Kind",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "info",
        children: $(e, ["kind"])
      })
    },
    {
      key: "status",
      label: "Status",
      render: (e) => $(e, ["status", "validation_status"], "recorded")
    },
    {
      key: "validation",
      label: "Validation",
      render: (e) => _s(vs(e, ["validation"]) ?? e.validation ?? null)
    },
    {
      key: "release",
      label: "Release",
      render: (e) => $(e, ["release_id", "id"])
    },
    {
      key: "custody",
      label: "Custody",
      render: (e) => {
        let t = gs(vs(e, ["evidence"]) ?? e.evidence);
        return t ? t.slice(0, 48) + (t.length > 48 ? "…" : "") : "metadata-only";
      }
    },
    {
      key: "created",
      label: "Created",
      render: (e) => I(e.created_at)
    }
  ];
  function o() {
    let n = {
      exported_at: (/* @__PURE__ */ new Date()).toISOString(),
      tenant_id: t.tenant_id ?? "ten_demo",
      coverage: i,
      attestation: r,
      records: e.releaseEvidence.map((e) => ({
        kind: $(e, ["kind"]),
        status: $(e, ["status"]),
        validation: _s(vs(e, ["validation"]) ?? e.validation ?? null),
        custody_uri: gs(vs(e, ["evidence"]) ?? e.evidence)
      }))
    };
    navigator.clipboard.writeText(JSON.stringify(n, null, 2));
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [/* @__PURE__ */ (0, R.jsx)(ia, { route: "release-evidence" }), n ? /* @__PURE__ */ (0, R.jsxs)(R.Fragment, { children: [
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Evidence kinds",
            value: `${i.recorded}/${i.expected}`,
            sub: i.kindsComplete ? "Inventory complete" : `${i.missing.length} kinds missing`,
            icon: le,
            tone: i.kindsComplete ? "success" : "warn"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Attestation",
            value: ys(r, ["signoff_status"], "unknown"),
            sub: "Staging readiness attestation",
            icon: N,
            tone: "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Production ready",
            value: String(r?.production_ready ?? "unknown"),
            sub: "Metadata-only release gate snapshot",
            icon: j,
            tone: "muted"
          })
        ]
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Gap ledger" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Kinds not yet attached to accepted release evidence for this tenant." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "product-form",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("p", {
            className: "muted",
            children: [
              "Recorded ",
              i.recorded,
              " of ",
              i.expected,
              " required kinds. Customer launch remains gated by staging, legal, SOC, and security signoffs."
            ]
          }),
          i.missing.length > 0 ? /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "queue-list",
            children: [i.missing.slice(0, 12).map((e) => /* @__PURE__ */ (0, R.jsx)("div", { children: /* @__PURE__ */ (0, R.jsx)(z, {
              tone: "warn",
              children: e
            }) }, e)), i.missing.length > 12 ? /* @__PURE__ */ (0, R.jsxs)("p", {
              className: "muted",
              children: [
                "…and ",
                i.missing.length - 12,
                " more kinds."
              ]
            }) : null]
          }) : /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "All required kinds are recorded for this tenant inventory snapshot."
          }),
          /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            onClick: o,
            children: "Copy gap ledger JSON"
          })
        ]
      })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Release evidence inventory" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Accepted kinds, validation summary, and custody URI previews without raw bodies." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: a,
        items: e.releaseEvidence,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: le,
          title: "No release evidence records.",
          body: "Operator evidence validators populate this inventory during release rehearsals."
        })
      }) })] }),
      r && /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Attestation snapshot" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "From `/v1/production-release-evidence/attestation`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "kv-list",
        children: [
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Signoff status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ys(r, ["signoff_status"]) })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Production ready" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: String(r.production_ready ?? "unknown") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Profile" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ys(r, ["profile"], "full") })] }),
          /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Checked at" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(r.checked_at ?? r.created_at) })] })
        ]
      })] })
    ] }) : /* @__PURE__ */ (0, R.jsx)(q, {
      icon: le,
      title: "Release evidence access required.",
      body: "Switch to owner, admin, SOC, or auditor role to inspect production release evidence."
    })]
  });
}
function Os({ data: e, config: t, session: n, onRefresh: r, staffSocSurface: i = !1 }) {
  let [a, o] = (0, C.useState)(""), [s, c] = (0, C.useState)(""), [l, u] = (0, C.useState)(""), [d, f] = (0, C.useState)(""), [p, m] = (0, C.useState)(() => $(e.highScale[0] ?? {}, ["id"], "")), [h, g] = (0, C.useState)(null), [_, v] = (0, C.useState)(null), y = i ? n.principal === "staff" && Mn(n) : n.role === "soc" && n.principal !== "staff";
  async function b(e, r = {}) {
    return i ? Ln(t, n, e, r) : L(t, n, e, r);
  }
  let x = e.highScale.find((e) => $(e, ["id"], "") === p) ?? e.highScale[0] ?? null, S = Array.isArray(x?.artifacts) ? x.artifacts : [];
  (0, C.useEffect)(() => {
    if (e.highScale.length === 0) {
      p && m("");
      return;
    }
    e.highScale.some((e) => $(e, ["id"], "") === p) || m($(e.highScale[0] ?? {}, ["id"], ""));
  }, [e.highScale, p]);
  let w = [
    {
      key: "id",
      label: "Request",
      render: (e) => $(e, ["id"])
    },
    {
      key: "state",
      label: "State",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: "warn",
        children: $(e, ["state"])
      })
    },
    {
      key: "target",
      label: "Target group",
      render: (e) => $(e, ["target_group_id"])
    },
    {
      key: "pack",
      label: "Pack",
      render: (e) => ys(e, ["authorization_pack_status", "overall"], "missing")
    },
    {
      key: "actions",
      label: "Actions",
      render: (e) => {
        let t = $(e, ["id"], ""), n = $(e, ["state"], ""), r = ys(e, ["authorization_pack_status", "overall"], "") === "accepted";
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [
            /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: t === p ? "default" : "secondary",
              onClick: () => m(t),
              children: "Select"
            }),
            ["submitted", "under_review"].includes(n) && r ? /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: a !== "",
              onClick: () => void E(t, "approve"),
              children: "Approve"
            }) : null,
            n === "approved" ? /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: a !== "",
              onClick: () => void E(t, "schedule", Bi()),
              children: "Schedule"
            }) : null,
            n === "scheduled" ? /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: a !== "",
              onClick: () => void E(t, "start"),
              children: "Start"
            }) : null,
            n === "running" ? /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: a !== "",
              onClick: () => void E(t, "stop"),
              children: "Stop"
            }) : null,
            n === "stopped" ? /* @__PURE__ */ (0, R.jsx)(B, {
              size: "sm",
              variant: "secondary",
              disabled: a !== "",
              onClick: () => void E(t, "close"),
              children: "Close"
            }) : null
          ]
        });
      }
    }
  ], T = [
    {
      key: "type",
      label: "Type",
      render: (e) => $(e, ["type"])
    },
    {
      key: "status",
      label: "Status",
      render: (e) => /* @__PURE__ */ (0, R.jsx)(z, {
        tone: $(e, ["status"]) === "accepted" ? "success" : "warn",
        children: $(e, ["status"])
      })
    },
    {
      key: "digest",
      label: "SHA-256",
      render: (e) => $(e, ["content_sha256"], "—").slice(0, 16)
    },
    {
      key: "actions",
      label: "Review",
      render: (e) => {
        let t = $(e, ["id"], "");
        return /* @__PURE__ */ (0, R.jsxs)("div", {
          className: "row-actions",
          children: [/* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            disabled: a !== "" || !p,
            onClick: () => void D(p, t, "accepted"),
            children: "Accept"
          }), /* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "ghost",
            disabled: a !== "" || !p,
            onClick: () => void D(p, t, "rejected"),
            children: "Reject"
          })]
        });
      }
    }
  ];
  async function E(e, t, n = {}) {
    if (!e) return null;
    o(`${t}-${e}`), u(""), c("");
    try {
      let i = await b(`/internal/soc/high-scale/${encodeURIComponent(e)}/${t}`, {
        method: "POST",
        body: n
      });
      return f(JSON.stringify(i, null, 2)), c(`SOC ${t} completed for ${e}.`), await r(), i;
    } catch (e) {
      let t = e.payload;
      return u(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "SOC action failed.")), null;
    } finally {
      o("");
    }
  }
  async function D(e, t, n) {
    !e || !t || await E(e, `artifacts/${t}/review`, {
      status: n,
      notes: `SOC ${n} via console`
    });
  }
  async function O(e) {
    if (e) {
      o(`adapter-${e}`), u("");
      try {
        let t = await b(`/internal/soc/high-scale/${encodeURIComponent(e)}/adapter-status`);
        g(t), f(JSON.stringify(t, null, 2));
      } catch (e) {
        u(e instanceof Error ? e.message : "Adapter status unavailable."), g(null);
      } finally {
        o("");
      }
    }
  }
  async function ee(e) {
    if (e.preventDefault(), !p) return;
    let t = String(new FormData(e.currentTarget).get("body") ?? "").trim();
    await E(p, "notes", { body: t }), e.currentTarget.reset();
  }
  async function te(e) {
    if (e.preventDefault(), !p) return;
    let t = new FormData(e.currentTarget), n = await E(p, "post-test-report", {
      impact_summary: String(t.get("impact_summary") ?? "").trim(),
      recommendations: String(t.get("recommendations") ?? "").trim(),
      residual_risk: String(t.get("residual_risk") ?? "").trim()
    });
    n && v(n);
  }
  async function ne(e) {
    o(e ? "kill-on" : "kill-off"), u(""), c("");
    try {
      let t = await b("/internal/soc/kill-switch", {
        method: "POST",
        body: {
          active: e,
          reason: e ? "SOC console activation" : "SOC console cleared"
        }
      });
      f(JSON.stringify(t, null, 2)), c(e ? "Kill switch activated." : "Kill switch cleared."), await r();
    } catch (e) {
      let t = e.payload;
      u(t?.message ?? t?.error ?? (e instanceof Error ? e.message : "Kill switch action failed."));
    } finally {
      o("");
    }
  }
  if (!y) {
    let t = !!(e.state?.kill_switch?.active ?? e.state?.kill_switch?.enabled);
    return /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "content",
      children: [
        /* @__PURE__ */ (0, R.jsx)(ia, { route: i ? "internal-soc" : "soc" }),
        /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: i ? "Staff SOC role required." : "SOC role required.",
          body: i ? "Sign in with a staff soc_analyst or soc_lead role to use the governed high-scale execution console." : "Switch the workspace role to soc to use the governed high-scale execution console."
        }),
        /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Kill switch" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Read-only tenant emergency-stop status. Activation and clearance require an SOC role." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "kv-list",
          children: [/* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Status" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: t ? "Active" : "Inactive" })] }), /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Reason" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: $(e.state?.kill_switch, ["reason"], "tenant-scoped emergency stop") })] })]
        })] })
      ]
    });
  }
  return /* @__PURE__ */ (0, R.jsxs)("div", {
    className: "content",
    children: [
      /* @__PURE__ */ (0, R.jsx)(ia, {
        route: i ? "internal-soc" : "soc",
        eyebrow: "SOC execution plane"
      }),
      /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "metric-grid three",
        children: [
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Queue",
            value: e.highScale.length,
            sub: "Governed high-scale requests",
            icon: De,
            tone: "warn"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Kill switch",
            value: e.state?.kill_switch?.active ?? e.state?.kill_switch?.enabled ? "ON" : "OFF",
            sub: $(e.state?.kill_switch, ["reason"], "tenant-scoped emergency stop"),
            icon: N,
            tone: e.state?.kill_switch?.active ?? e.state?.kill_switch?.enabled ? "danger" : "success"
          }),
          /* @__PURE__ */ (0, R.jsx)(X, {
            label: "Open findings",
            value: e.state?.open_findings ?? e.findings.length,
            sub: "Customer posture while tests run",
            icon: j,
            tone: "info"
          })
        ]
      }),
      (s || l) && /* @__PURE__ */ (0, R.jsx)("div", {
        className: l ? "form-banner error" : "form-banner",
        children: l || s
      }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Kill switch" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Tenant-scoped emergency stop for governed high-scale adapter runs." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
        className: "row-actions",
        children: [/* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: "danger",
          disabled: a !== "",
          onClick: () => void ne(!0),
          children: "Activate"
        }), /* @__PURE__ */ (0, R.jsx)(B, {
          size: "sm",
          variant: "secondary",
          disabled: a !== "",
          onClick: () => void ne(!1),
          children: "Clear"
        })]
      })] }),
      /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "High-scale queue" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "SOC-only lifecycle actions call `/internal/soc/high-scale/*` routes." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
        columns: w,
        items: e.highScale,
        empty: /* @__PURE__ */ (0, R.jsx)(q, {
          icon: N,
          title: "No high-scale requests.",
          body: "Customer requests appear here after intake and authorization-pack review."
        })
      }) })] }),
      x ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Authorization artifacts" }), /* @__PURE__ */ (0, R.jsxs)(G, { children: [
          "Review metadata-only artifacts for ",
          $(x, ["id"]),
          "."
        ] })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)(J, {
          columns: T,
          items: S,
          empty: /* @__PURE__ */ (0, R.jsx)(q, {
            icon: j,
            title: "No artifacts uploaded.",
            body: "Customer authorization pack artifacts appear after metadata-only upload."
          })
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Adapter status" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Governed adapter dry-run telemetry from `/internal/soc/high-scale/:id/adapter-status`." })] }), /* @__PURE__ */ (0, R.jsxs)(K, {
          className: "product-form",
          children: [/* @__PURE__ */ (0, R.jsx)(B, {
            size: "sm",
            variant: "secondary",
            disabled: a !== "",
            onClick: () => void O(p),
            children: "Refresh adapter status"
          }), h ? /* @__PURE__ */ (0, R.jsxs)("div", {
            className: "kv-list",
            children: [
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "State" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: ys(h, ["adapter", "state"], $(h, ["state"])) })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Traffic generated" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: String(ys(h, ["adapter", "traffic_generated"], "false")) })] }),
              /* @__PURE__ */ (0, R.jsxs)("div", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Last updated" }), /* @__PURE__ */ (0, R.jsx)("strong", { children: I(h.updated_at ?? h.checked_at) })] })
            ]
          }) : /* @__PURE__ */ (0, R.jsx)("p", {
            className: "muted",
            children: "Adapter status not loaded yet."
          })]
        })] })]
      }) : null,
      x ? /* @__PURE__ */ (0, R.jsxs)("div", {
        className: "split",
        children: [/* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "SOC notes" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Metadata-only notes are redacted before persistence." })] }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: ee,
          children: [/* @__PURE__ */ (0, R.jsxs)("label", {
            className: "full",
            children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Note" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
              name: "body",
              rows: 4,
              placeholder: "Execution observation or coordination note",
              required: !0
            })]
          }), /* @__PURE__ */ (0, R.jsx)("div", {
            className: "form-actions full",
            children: /* @__PURE__ */ (0, R.jsx)(B, {
              type: "submit",
              disabled: a !== "",
              children: "Add SOC note"
            })
          })]
        }) })] }), /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsxs)(U, { children: [/* @__PURE__ */ (0, R.jsx)(W, { children: "Post-test report" }), /* @__PURE__ */ (0, R.jsx)(G, { children: "Required before close when request is stopped." })] }), /* @__PURE__ */ (0, R.jsxs)(K, { children: [/* @__PURE__ */ (0, R.jsxs)("form", {
          className: "product-form",
          onSubmit: te,
          children: [
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Impact summary" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "impact_summary",
                rows: 3,
                required: !0
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", {
              className: "full",
              children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Recommendations" }), /* @__PURE__ */ (0, R.jsx)("textarea", {
                name: "recommendations",
                rows: 3
              })]
            }),
            /* @__PURE__ */ (0, R.jsxs)("label", { children: [/* @__PURE__ */ (0, R.jsx)("span", { children: "Residual risk" }), /* @__PURE__ */ (0, R.jsx)("input", {
              name: "residual_risk",
              defaultValue: "low"
            })] }),
            /* @__PURE__ */ (0, R.jsx)("div", {
              className: "form-actions full",
              children: /* @__PURE__ */ (0, R.jsx)(B, {
                type: "submit",
                disabled: a !== "",
                children: "Save post-test report"
              })
            })
          ]
        }), _ ? /* @__PURE__ */ (0, R.jsxs)("p", {
          className: "muted",
          children: [
            "Report ",
            $(_, ["id"]),
            " saved for ",
            $(_, ["high_scale_request_id"]),
            "."
          ]
        }) : null] })] })]
      }) : null,
      d ? /* @__PURE__ */ (0, R.jsxs)(H, { children: [/* @__PURE__ */ (0, R.jsx)(U, { children: /* @__PURE__ */ (0, R.jsx)(W, { children: "Action output" }) }), /* @__PURE__ */ (0, R.jsx)(K, { children: /* @__PURE__ */ (0, R.jsx)("pre", {
        className: "codeblock",
        children: d
      }) })] }) : null
    ]
  });
}
//#endregion
//#region apps/web/react/src/pages/router.tsx
function ks({ route: e, data: t, config: n, session: r, onRefresh: i }) {
  return e === "dashboard" ? /* @__PURE__ */ (0, R.jsx)(la, { data: t }) : e === "onboarding" ? /* @__PURE__ */ (0, R.jsx)(ua, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "environments" ? /* @__PURE__ */ (0, R.jsx)(wa, { data: t }) : e === "target-groups" ? /* @__PURE__ */ (0, R.jsx)(da, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "agents" ? /* @__PURE__ */ (0, R.jsx)(ls, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : [
    "target-group-detail",
    "agent-detail",
    "run-detail",
    "waf-asset-detail",
    "discovery-entity",
    "tenant-detail",
    "cve-detail",
    "supply-chain-detail"
  ].includes(e) ? /* @__PURE__ */ (0, R.jsx)(Xa, {
    route: e,
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "test-policies" ? /* @__PURE__ */ (0, R.jsx)(Ta, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : [
    "checks",
    "runs",
    "findings",
    "evidence"
  ].includes(e) ? /* @__PURE__ */ (0, R.jsx)(us, {
    route: e,
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : [
    "waf-posture",
    "cve-pipeline",
    "supply-chain",
    "remediation",
    "discovery"
  ].includes(e) ? /* @__PURE__ */ (0, R.jsx)(ds, {
    route: e,
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "integrations" ? /* @__PURE__ */ (0, R.jsx)(Da, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "reports" ? /* @__PURE__ */ (0, R.jsx)(ya, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "report-detail" ? /* @__PURE__ */ (0, R.jsx)(Za, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "high-scale" ? /* @__PURE__ */ (0, R.jsx)(_a, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "soc" ? /* @__PURE__ */ (0, R.jsx)(Os, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "notifications" ? /* @__PURE__ */ (0, R.jsx)(Ts, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "audit" ? /* @__PURE__ */ (0, R.jsx)(Es, {
    data: t,
    session: r
  }) : e === "release-evidence" ? /* @__PURE__ */ (0, R.jsx)(Ds, {
    data: t,
    session: r
  }) : e === "support" ? /* @__PURE__ */ (0, R.jsx)(Oa, {
    data: t,
    session: r
  }) : e === "subscription" ? /* @__PURE__ */ (0, R.jsx)(Na, { data: t }) : e === "internal-soc" ? /* @__PURE__ */ (0, R.jsx)(Os, {
    data: t,
    config: n,
    session: r,
    onRefresh: i,
    staffSocSurface: !0
  }) : e === "admin" ? /* @__PURE__ */ (0, R.jsx)(Pa, {
    route: e,
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : e === "settings" ? /* @__PURE__ */ (0, R.jsx)(Ca, {
    data: t,
    config: n,
    session: r,
    onRefresh: i
  }) : /* @__PURE__ */ (0, R.jsx)(fa, {
    route: e,
    data: t
  });
}
//#endregion
//#region apps/web/react/src/App.tsx
function As() {
  return /* @__PURE__ */ (0, R.jsx)("div", {
    className: "loading-screen",
    children: /* @__PURE__ */ (0, R.jsxs)("div", {
      className: "loading-card",
      children: [
        /* @__PURE__ */ (0, R.jsx)("div", { className: "spinner" }),
        /* @__PURE__ */ (0, R.jsx)("strong", { children: "Loading AstraNull" }),
        /* @__PURE__ */ (0, R.jsx)("p", { children: "Preparing the readiness console." })
      ]
    })
  });
}
function js(e) {
  return [
    "/",
    "/landing.html",
    "/login",
    "/login.html",
    "/signup",
    "/signup.html",
    "/signup-status",
    "/internal/admin/login",
    "/staff-login.html"
  ].includes(e);
}
function Ms() {
  let [e, t] = (0, C.useState)(() => Kn()), [n, r] = (0, C.useState)(() => window.location.pathname), [i, a] = (0, C.useState)(null), [o, s] = (0, C.useState)(() => Tn()), [c, l] = (0, C.useState)(Vn), [u, d] = (0, C.useState)(!0), f = (0, C.useMemo)(() => o ?? {}, [o]), p = (0, C.useCallback)(async (t, n, r) => {
    if (t) try {
      let i = await Bn(t, n, { route: r ?? e });
      l(i);
    } catch (e) {
      l((t) => ({
        ...t,
        loaded: !0,
        error: e instanceof Error ? e.message : "Could not load workspace data."
      }));
    }
  }, [e]);
  (0, C.useEffect)(() => {
    let e = !0;
    async function t() {
      let t = await An(Sn(window.location.pathname));
      if (!e) return;
      if (t.redirectToLogin && !js(window.location.pathname)) {
        window.location.replace(t.loginUrl ?? "/login");
        return;
      }
      let n = t.config, r = t.session;
      a(n), s(r), !js(window.location.pathname) && r && await p(n, r, Kn()), e && d(!1);
    }
    return t().catch((t) => {
      e && (l({
        ...Vn,
        loaded: !0,
        error: t instanceof Error ? t.message : "Could not initialize the portal."
      }), d(!1));
    }), () => {
      e = !1;
    };
  }, [p]), (0, C.useEffect)(() => {
    function e() {
      let e = Kn(), n = Tn();
      tr(n?.role ?? f.role, e, {
        principal: n?.principal ?? f.principal,
        staffRole: n?.staff_role ?? f.staff_role
      }) ? t(e) : (window.location.replace(`${window.location.pathname}${window.location.search}#dashboard`), t("dashboard")), r(window.location.pathname);
    }
    return window.addEventListener("hashchange", e), window.addEventListener("popstate", e), () => {
      window.removeEventListener("hashchange", e), window.removeEventListener("popstate", e);
    };
  }, [
    f.principal,
    f.role,
    f.staff_role
  ]), (0, C.useEffect)(() => {
    if (!i || u) return;
    let t = Tn();
    t && On(t) !== On(o) && (s(t), p(i, t, e));
  }, [
    e,
    n,
    i,
    u,
    p,
    o
  ]), (0, C.useEffect)(() => {
    if (u || !i) return;
    let n = f.role;
    tr(n, e, {
      principal: f.principal,
      staffRole: f.staff_role
    }) || (window.location.replace(`${window.location.pathname}${window.location.search}#dashboard`), t("dashboard"));
  }, [
    u,
    i,
    e,
    f.principal,
    f.role,
    f.staff_role
  ]);
  function m(e) {
    let t = {
      ...f,
      mode: f.mode ?? "dev-headers",
      principal: "customer",
      tenant_id: f.tenant_id ?? "ten_demo",
      user_id: f.user_id ?? "usr_admin",
      role: e
    };
    En(t), s(t), p(i, t);
  }
  return u || !i ? /* @__PURE__ */ (0, R.jsx)(As, {}) : n === "/" || n === "/landing.html" ? /* @__PURE__ */ (0, R.jsx)(Sr, { config: i }) : n === "/login" || n === "/login.html" ? /* @__PURE__ */ (0, R.jsx)(Cr, { config: i }) : n === "/signup" || n === "/signup.html" ? /* @__PURE__ */ (0, R.jsx)(Tr, { config: i }) : n === "/signup-status" ? /* @__PURE__ */ (0, R.jsx)(Er, {}) : n === "/internal/admin/login" || n === "/staff-login.html" ? /* @__PURE__ */ (0, R.jsx)(Dr, { config: i }) : /* @__PURE__ */ (0, R.jsx)(pr, {
    route: e,
    session: f,
    data: c,
    onRouteChange: t,
    onRoleChange: m,
    onRefresh: () => void p(i, f, e),
    children: /* @__PURE__ */ (0, R.jsx)(ks, {
      route: e,
      data: c,
      config: i,
      session: f,
      onRefresh: () => p(i, f, e)
    })
  });
}
//#endregion
//#region apps/web/react/src/main.tsx
(0, Ie.createRoot)(document.getElementById("root")).render(/* @__PURE__ */ (0, R.jsx)(C.StrictMode, { children: /* @__PURE__ */ (0, R.jsx)(Ms, {}) }));
//#endregion
