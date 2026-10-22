(window.Dmdbase_CDC = {}),
  (window.Dmdbase_CDC = {
    cookieName: "dmdbase_cdc",
    dimensions: {},
    logging: !1,
    enableTNT: !1,
    enableStandard: !1,
    enableAnalytics: !0,
    DB_DEFAULT_VALUE: "ISP Visitor",
    NOT_IN_AWLIST: "Not In List",
    NOT_ASSIGNED_AWLIST_VALUE: "In List No Value",
    CompanyProfile: {},
    targetAttributes: [
      "demandbase_sid",
      "company_name",
      "industry",
      "sub_industry",
      "employee_range",
      "revenue_range",
      "audience",
      "audience_segment",
      "state",
      "country_name",
      "marketing_alias",
      "b2b",
      "b2c",
      "web_site",
      "watch_list_account_type",
      "watch_list_account_status",
    ],
    useStorage: !0,
    useCookie: !0,
    targetReady: !1,
    init: function () {
      "true" === this.cdc_getParamByName("cdc_debug") && (this.logging = !0);
    },
    setupDimensions: function () {
      (this.dimensions.set1 = {
        company_id: 12,
        company_name: 40,
        industry: 40,
        sub_industry: 40,
        employee_range: 30,
        revenue_range: 30,
        audience: 30,
        audience_segment: 30,
      }),
        (this.dimensions.set2 = {
          marketing_alias: 30,
          primary_sic: 30,
          employee_count: 30,
          annual_sales: 30,
          phone: 30,
          fax: 30,
          efx_id: 30,
          fortune_1000: 30,
        }),
        (this.dimensions.set3 = {
          street_address: 30,
          city: 30,
          state: 30,
          zip: 30,
          country: 30,
          country_name: 30,
          company_status: 30,
          company_type: 30,
        }),
        (this.dimensions.set4 = {
          registry_company_name: 30,
          registry_city: 30,
          registry_state: 30,
          registry_zip_code: 30,
          registry_area_code: 30,
          registry_dma_code: 30,
          registry_country: 30,
          registry_country_code: 30,
        }),
        (this.dimensions.set5 = {
          registry_country_code3: 30,
          registry_latitude: 30,
          registry_longitude: 30,
          isp: 30,
          primary_naics: 30,
          company_linkedin_profile: 30,
          information_level: 30,
          stock_ticker: 30,
        }),
        (this.dimensions.set6 = {
          web_site: 30,
          company_type: 30,
          business_structure: 30,
          placeholder3: 30,
          parent_id: 30,
          parent_name: 30,
          ultimate_parent_id: 30,
          ultimate_parent_name: 30,
        }); //!!!!! modify this to match what's in the UI within the Data Connector setup in Adobe
    },
    callback: function (e) {
      if (e)
        try {
          window.Dmdbase_CDC.init(),
            (e = this.flatten(e)),
            (window.Dmdbase_CDC.CompanyProfile = e),
            this.enableAnalytics &&
              this.setAnalytics(window.Dmdbase_CDC.CompanyProfile),
            this.enableTNT && this.setMbox(window.Dmdbase_CDC.CompanyProfile);
        } catch (t) {
          window.console && this.logging && console.log("DB _ " + t.message);
        }
    },
    loadAnalytics: function () {
      this.setAnalytics(window.Dmdbase_CDC.CompanyProfile);
    },
    setAnalytics: function (e) {
      try {
        if ((this.setupDimensions(), window.sessionStorage)) {
          var t = sessionStorage.getItem("s_dmdbase"),
            i = sessionStorage.getItem("s_dmdbase_detail");
          i && "Basic" === i && this.storeSessionData(e),
            !t && this.isCookieSet(this.cookieName) && this.storeSessionData(e);
        }
        this.isCookieSet(this.cookieName) || this.storeSessionData(e);
      } catch (s) {
        window.console && this.logging && console.log("DB _ " + s.message);
      }
    },
    storeSessionData: function (e) {
      var t = this.buildDelimitedStrings(":", e);
      if (
        (this.isCookieSet(this.cookieName) ||
          this.saveToCookie(this.cookieName, "DBSET", 1),
        (Dmdbase_CDC.contextData = t),
        window.sessionStorage && this.useStorage)
      ) {
        sessionStorage.setItem("s_dmdbase", Dmdbase_CDC.contextData[0]),
          sessionStorage.setItem("s_dmdbase_detail", e.information_level);
        for (var i = 1; i < Dmdbase_CDC.contextData.length; i++)
          sessionStorage.setItem(
            "s_dmdbase_custom" + i,
            Dmdbase_CDC.contextData[i]
          );
      }
    },
    setMbox: function (e) {
      try {
        this.enableStandard
          ? this.set_mbox_variables(e)
          : null !== window.TNT &&
            "object" == typeof window.TNT &&
            this.set_mbox_variables(e);
      } catch (t) {
        window.console && this.logging && console.log("DB _ " + t.message);
      }
    },
    flatten: function (e) {
      for (var t in e)
        if ("object" == typeof e[t] && null !== e[t] && e.hasOwnProperty(t)) {
          for (var i in e[t])
            e[t].hasOwnProperty(i) && (e[t + "_" + i] = e[t][i]);
          delete e[t];
        }
      return e;
    },
    saveToCookie: function (e, t) {
      var i = new Date();
      i.setTime(i.getTime() + 18e5);
      var s = "; expires=" + i.toGMTString(),
        n = document.location.href,
        a = "; domain=" + this.getDomain(n);
      document.cookie = e + "=" + encodeURIComponent(t) + s + a + "; path=/";
    },
    getCookieByName: function (e) {
      e += "=";
      for (var t = document.cookie.split(";"), i = 0; i < t.length; i++) {
        for (var s = t[i]; " " == s.charAt(0); ) s = s.substring(1);
        if (-1 != s.indexOf(e))
          return decodeURIComponent(s.substring(e.length, s.length));
      }
      return "";
    },
    getHostName: function (e) {
      var t = e.match(/:\/\/(www[0-9]?\.)?(.[^/:]+)/i);
      return null != t &&
        t.length > 2 &&
        "string" == typeof t[2] &&
        t[2].length > 0
        ? t[2]
        : null;
    },
    getDomain: function (e) {
      var t = this.getHostName(e),
        i = t;
      if (null != t) {
        var s = t.split(".").reverse();
        null != s &&
          s.length > 1 &&
          ((i = "." + s[1] + "." + s[0]),
          -1 != t.toLowerCase().indexOf(".co.uk") &&
            s.length > 2 &&
            (i = "." + s[2] + "." + i));
      }
      return i;
    },
    isCookieSet: function (e) {
      var t = this.getCookieByName(e);
      return t && "undefined" != t;
    },
    buildDelimitedStrings: function (e, t) {
      var i = this.dimensions,
        s = [];
      for (var n in i)
        if (i.hasOwnProperty(n)) {
          var a = "";
          for (var r in i[n])
            if (i[n].hasOwnProperty(r)) {
              var o = "";
              o =
                -1 != r.indexOf("watch_list") &&
                "Detailed" === t.information_level &&
                t.hasOwnProperty(r)
                  ? this.truthy(t[r], this.NOT_ASSIGNED_AWLIST_VALUE)
                  : -1 == r.indexOf("watch_list") ||
                    "Detailed" !== t.information_level ||
                    t.hasOwnProperty(r)
                  ? this.truthy(t[r], this.DB_DEFAULT_VALUE)
                  : this.truthy(t[r], this.NOT_IN_AWLIST);
              var c = i[n][r];
              a += (o = this.resizeStr(o, c)) + e;
            }
          (a = a.substring(0, a.length - 1)),
            (a = this.resizeStr(a, 255)),
            s.push(a);
        }
      return s;
    },
    resizeStr: function (e, t) {
      return e.length > t && (e = e.substring(0, t)), e;
    },
    truthy: function (e, t) {
      return e || (!1 === e ? e : t);
    },
    cdc_getParamByName: function (e) {
      var t = RegExp(
        "[\\?&]" +
          (e = e.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]")) +
          "=([^&#]*)"
      ).exec(location.search);
      return null === t ? "" : decodeURIComponent(t[1].replace(/\+/g, " "));
    },
    set_mbox_variables: function (e) {
      try {
        var t,
          i = "";
        for (var s in e)
          if (e.hasOwnProperty(s) && -1 != this.targetAttributes.indexOf(s)) {
            var n = "profile." + s + "=" + e[s] + ",";
            i += n;
          }
        (i = i.split(",")),
          this.enableStandard
            ? ((window.targetPageParams = function () {
                return i;
              }),
              window.targetPageParams(),
              (window.Dmdbase_CDC.targetReady = !0))
            : "undefined" != typeof mboxFactoryDefault &&
              (t = mboxFactoryDefault.getUrlBuilder()).addParameters(i);
      } catch (a) {
        console.log(a);
      }
    },
  });
