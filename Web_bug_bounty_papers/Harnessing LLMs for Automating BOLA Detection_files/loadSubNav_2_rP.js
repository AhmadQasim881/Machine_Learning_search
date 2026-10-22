function loadUnit42SubMenu(){
    async function renderSubMenu() {
        var $rootNavContainer = $('#main-nav-menu-cont');
        if (!$rootNavContainer.length) return; 
        
        var rootCont = $rootNavContainer[0];
        var newNavEl = document.createElement('div');
        newNavEl.classList.add("secondaryNavComp");
        newNavEl.setAttribute("style", "height: 0;")
        
        // 1. Inject the necessary stylesheets from the original nav site
        var cssPaths = [
            maindomain_lang + "/etc.clientlibs/panClean/dynamicComponents/secondaryNavComp/clientlibs/panClean/criticalTop.min.css",
            maindomain_lang + "/etc.clientlibs/panClean/dynamicComponents/secondaryNavComp/clientlibs/panClean/defered.min.css"
        ];
        
        cssPaths.forEach(function(href) {
            if (!document.querySelector('link[href="' + href + '"]')) {
                var link = document.createElement('link');
                link.rel = 'stylesheet';
                link.href = href;
                document.head.appendChild(link);
            }
        });

        var customStylesId = "unit42-custom-nav-styles";
        if (!document.getElementById(customStylesId)) {
            var styleEl = document.createElement('style');
            styleEl.id = customStylesId;
            styleEl.innerHTML = `
                @media screen and (max-width: 949px) {
                    .blog-editor .be__wrapper .be__nav .be__nav-wrapper.is-sticky {
                        top: 60px;   
                    }   
                }
                .mainNavigationComp .cat-overview-link {
                    display: none !important;
                }
                .mainNavigationComp .pt-3 {
                    padding-top: 16px !important;
                }
                .secondaryNavComp .btn {
                    border-radius: 1.75rem;
                    height: auto;
                    flex-grow: 0;
                    flex-shrink: 0;
                    display: inline-flex;
                    font-family: var(--font-primary);
                    font-size: .875rem;
                    font-weight: 600;
                    line-height: 140%;
                    letter-spacing: .02rem;
                    color: #141414;
                    text-align: center;
                    vertical-align: middle;
                    user-select: none;
                    background-color: transparent;
                    transition: box-shadow .15s ease-in-out;
                    height: auto;
                }
                .secondaryNavComp .btn-primary {
                    color: #fff !important;
                    background-color: #d9551d;
                    background-image: linear-gradient(to right, #d9551d 25%, #d64420 75%);
                }
                .btn-outline-light {
                    color: #141414;
                    border: 2px solid #141414;
                    background-color: transparent;
                }
                .btn-outline-light:hover {
                    color: #ffffff;
                    background-color: #141414;
                    border-color: #141414;
                }
                .secondaryNavComp .w-100 {width: auto !important;}
                @media (max-width: 1199.98px) {
                    .secondaryNavComp .secondary-nav{
                        position: fixed !important;
                    }
                }
                @media screen and (min-width: 950px) {
                    .blog-editor .be__wrapper .be__nav .be__nav-wrapper {
                        position: sticky;
                        top: 5.125rem;
                    }
                }
                /* xl breakpoint (1200px and up) */
                @media (min-width: 1200px) {
                    .d-xl-none { display: none !important; }
                    .d-xl-flex { display: flex !important; }
                    .flex-xl-row { flex-direction: row !important; }
                    .align-items-xl-center { align-items: center !important; }

                    .secondaryNavComp .secondary-nav .right-action-section .dropdown .dropdown-menu {
                        top: 3rem !important;
                    }
                    .secondaryNavComp .secondary-nav .nav .nav-item .nav-link>span {
                        top: 12px;
                    }
                }

            `;
            document.head.appendChild(styleEl);
        }

        // 2. Setup the HTML data
        var data = `
    <div class="nav-overlay" id="navOverlay"></div>

    <section class="secondary-nav d-flex align-items-center justify-content-between position-absolute background-white theme-light base-comp-spacer spacer-none tablet-spacer-unset mobile-spacer-unset bottom-spacer-none bottom-tablet-spacer-unset bottom-mobile-spacer-unset" data-type="unit42" id="id_null" style="position: fixed; top: 0px; width: 100%; z-index: 999; transition: opacity 0.5s, transform 0.5s, top 0.5s; opacity: 0; transform: translateY(0px); pointer-events: auto;">

            <div class="col-auto d-flex align-items-center left-brand-section">
                <a href="/" class="brand-logo mr-3 pr-3 text-decoration-none logo-light " data-page-track="true" data-page-track-value="en_us:sub-nav:logo">
                    <img src="${maindomain_lang}/etc/clientlibs/clean/imgs/unit42-logo-dark.svg" alt="unit42 logo" class="img-fluid">
                </a>
            </div>

            <div class="col-auto d-flex align-items-center d-xl-none pr-3">
                <button class="navbar-toggler p-0 border-0 bg-transparent" type="button" data-toggle="collapse" data-target="#secondaryNavDrawer" aria-controls="secondaryNavDrawer" aria-expanded="false" aria-label="Toggle navigation">open</button>
            </div>

            <div class="col-auto collapse right-action-section flex-grow-0" id="secondaryNavDrawer">
                
                <div class="mobile-drawer-inner d-flex flex-column flex-xl-row align-items-xl-center">
                    
                    <div class="nav d-flex flex-column flex-xl-row align-items-xl-center">
                        <div class="anchor nav-item text-xl-center text-light">
                            <a href="/category/threat-research/" data-page-track="true" data-page-track-value="en_us:sub-nav:0:threat research" aria-label="Threat research" class="nav-link text-light ">
                                <span>Threat Research</span>
                            </a>
                        </div>
                    
                        <div class="anchor nav-item text-xl-center text-light">
                            <a href="/category/top-cyberthreats/" data-page-track="true" data-page-track-value="en_us:sub-nav:1:high profile threats" aria-label="High profile threats" class="nav-link text-light ">
                                <span>High Profile Threats</span>
                            </a>
                        </div>
                    
                        <div class="anchor nav-item text-xl-center text-light">
                            <a href="/category/insights/" data-page-track="true" data-page-track-value="en_us:sub-nav:2:insights" aria-label="Insights" class="nav-link text-light ">
                                <span>Insights</span>
                            </a>
                        </div>
                    
                        <div class="anchor nav-item text-xl-center text-light">
                            <a href="/threat-bulletin/" data-page-track="true" data-page-track-value="en_us:sub-nav:3:trend reports" aria-label="Trend Reports" class="nav-link text-light ">
                                <span>Trend Reports</span>
                            </a>
                        </div>
                    
                        <div class="anchor nav-item text-xl-center text-light">
                            <a href="/category/threat-actor-groups/" data-page-track="true" data-page-track-value="en_us:sub-nav:4:threat actor groups" aria-label="Threat Actor Groups" class="nav-link text-light ">
                                <span>Threat Actor Groups</span>
                            </a>
                        </div>
                    </div>
                    

                    <div class="right-buttons d-flex justify-content-center justify-content-xl-end pl-xl-3 border-left-xl p-3 border-top border-xl-0">
                        <a href="${maindomain_lang}/unit42/contact-unit42" target="_self" data-page-track="true" data-page-track-value="en_us:sub-nav:right-button:under attack?" class="btn flex-fill mx-1 flex-xl-grow-0 ml-xl-2 btn-primary no-wrap" rel="noopener">
                            Under Attack?
                        </a>
                    </div>
                </div>
            </div>
    </section>
        `;

        await window.PAN_Clean_Util.yieldToMain(0);
        
        var $newNavEl = $(newNavEl);
        $newNavEl.html(data);

        rootCont.after(newNavEl);

        // 3. Inject JS after the markup is appended to the DOM
        var jsPath = maindomain_lang + "/etc.clientlibs/panClean/dynamicComponents/secondaryNavComp/clientlibs/panClean/defered.min.js";
        if (!document.querySelector('script[src="' + jsPath + '"]')) {
            var scriptEl = document.createElement('script');
            scriptEl.src = jsPath;
            document.body.appendChild(scriptEl);
        }

        /* Custom event to detect when asyncNav has been inserted into DOM */
        const asyncNavEvent = new Event("asyncSubNavLoaded");
        // Dispatch the event.
        $rootNavContainer[0].dispatchEvent(asyncNavEvent);

        $(".sticky-nav").hide();
    }

    // Check if the main nav has already loaded.
    // If it has, run the render function immediately.
    if ($('#PAN_2021_NAV_ASYNC').length > 0) {
        renderSubMenu();
    } else {
        // Otherwise, wait for the event to be dispatched.
        document.addEventListener("asyncNavLoaded", renderSubMenu);
    }
}
loadUnit42SubMenu();