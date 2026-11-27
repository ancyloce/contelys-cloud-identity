<#--
  Keycloak 26.8.2's theme/keycloak.v2/login/password-commons.ftl, under Apache-2.0, whose text is
  realm/themes/LICENSE-Keycloak, with one change: the box "Sign out from other devices" is checked by
  default (value=true), so that a password reset ends the person's other sessions unless they uncheck
  it (design sections 04 and 09). A scenario reads the box back at each new test baseline.
-->
<#import "field.ftl" as field>
<#macro logoutOtherSessions>
    <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
        <div class="${properties.kcFormOptionsWrapperClass!}"> 
            <@field.checkbox name="logout-sessions" label=msg("logoutOtherSessions") value=true />
        </div>
    </div>
</#macro>
