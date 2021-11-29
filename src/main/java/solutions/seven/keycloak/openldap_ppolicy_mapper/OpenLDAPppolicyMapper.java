package solutions.seven.keycloak.openldap_ppolicy_mapper;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.TxAwareLDAPUserModelDelegate;

import javax.naming.AuthenticationException;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class OpenLDAPppolicyMapper extends AbstractLDAPStorageMapper {

    private static final Logger logger = Logger.getLogger(OpenLDAPppolicyMapper.class);
    public static final String LDAP_PPOLICY_LOCK_TIME = "pwdLockoutDuration";
    public static final String LDAP_TIMESTAMP_FORMAT = "yyyyMMddkk[mm[ss]][.S]X";
    public static final String CONFIG_LDAP_LOCKOUT_DURATION = "ldap.ppolicy.lockout.duration";

    public OpenLDAPppolicyMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        query.addReturningLdapAttribute(LDAPConstants.PWD_LAST_SET);
        query.addReturningLdapAttribute(LDAPConstants.USER_ACCOUNT_CONTROL);

        // This needs to be read-only and can be set to writable just on demand
        query.addReturningReadOnlyLdapAttribute(LDAPConstants.PWD_LAST_SET);

        if (ldapProvider.getEditMode() != UserStorageProvider.EditMode.WRITABLE) {
            query.addReturningReadOnlyLdapAttribute(LDAPConstants.USER_ACCOUNT_CONTROL);
        }
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        return new OpenLDAPUserModelDelegate(delegate, ldapUser);
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {

    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {

    }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user, AuthenticationException ldapException,
            RealmModel realm) {
        logger.debug(ldapException.getMessage());

        /*
         * String exceptionMessage = ldapException.getMessage(); Matcher m =
         * AUTH_EXCEPTION_REGEX.matcher(exceptionMessage); if (m.matches()) { String
         * errorCode = m.group(1); return processAuthErrorCode(errorCode, user); } else
         * { return false; }
         */
        return false;
    }

    protected boolean processAuthErrorCode(String errorCode, UserModel user) {
        if (errorCode.equals("533")) {
            // User is disabled in MSAD. Set him to disabled in KC as well
            if (user.isEnabled()) {
                user.setEnabled(false);
            }
            return true;
        }

        return false;
    }

    public class OpenLDAPUserModelDelegate extends TxAwareLDAPUserModelDelegate {

        private final LDAPObject ldapUser;
        private DateTimeFormatter ldapFormatter;

        public OpenLDAPUserModelDelegate(UserModel delegate, LDAPObject ldapUser) {
            super(delegate, ldapProvider, ldapUser);
            this.ldapUser = ldapUser;
            this.ldapFormatter = DateTimeFormatter.ofPattern(LDAP_TIMESTAMP_FORMAT);
        }

        @Override
        public boolean isEnabled() {
            boolean kcEnabled = super.isEnabled();
            LocalDateTime lockedTime = getPwdLockedTime();
            long lockoutDuration = mapperModel.get(CONFIG_LDAP_LOCKOUT_DURATION, 0);

            if (lockedTime != null) {

                if (lockoutDuration > 0) {
                    LocalDateTime unlockedTime = lockedTime.minusSeconds(lockoutDuration);
                    return kcEnabled && unlockedTime.isBefore(LocalDateTime.now(ZoneId.of("UTC")));
                } else {
                    return kcEnabled && lockedTime.isAfter(LocalDateTime.now(ZoneId.of("UTC")));
                }
            } else {
                return kcEnabled;
            }
        }

        @Override
        public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);

            if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {
                OpenLDAPppolicyMapper.logger.debugf("Propagating enabled=%s for user '%s' to OpenLDAP", enabled,
                        ldapUser.getDn().toString());

                if (enabled) {
                    ldapUser.setSingleAttribute(LDAP_PPOLICY_LOCK_TIME, null);
                } else {
                    ldapUser.setSingleAttribute(LDAP_PPOLICY_LOCK_TIME, "000001010000Z");
                }

                markUpdatedAttributeInTransaction(LDAPConstants.ENABLED);
            }
        }

        protected LocalDateTime getPwdLockedTime() {
            String lockTimestamp = ldapUser.getAttributeAsString(LDAP_PPOLICY_LOCK_TIME);
            if (lockTimestamp != null) {
                return LocalDateTime.parse(lockTimestamp, this.ldapFormatter);
            } else {
                return null;
            }

        }

    }

}
