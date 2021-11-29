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

import java.time.ZonedDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class OpenLDAPppolicyMapper extends AbstractLDAPStorageMapper {

    private static final Logger logger = Logger.getLogger(OpenLDAPppolicyMapper.class);
    public static final String LDAP_PPOLICY_LOCK_TIME = "pwdAccountLockedTime";
    public static final String LDAP_TIMESTAMP_FORMAT = "yyyyMMddkkmmss[.SSS]X";
    // this particular timestamp signifies a ermant block by the admin and can only
    // be removed by the admin
    public static final String LDAP_LOCKOUT_TIMESTAMP = "000001010000Z";
    public static final String CONFIG_LDAP_LOCKOUT_DURATION = "ldap.ppolicy.lockout.duration";

    public OpenLDAPppolicyMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        query.addReturningLdapAttribute(LDAP_PPOLICY_LOCK_TIME);
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
        long lockoutDuration = mapperModel.get(CONFIG_LDAP_LOCKOUT_DURATION, 0);

        if (ldapException.getMessage().equals("[LDAP: error code 49 - Invalid Credentials]")) {
            // OpenLDAP doesn't tell us in the error message if the Account is locked or the
            // username/password are wrong, so we have to check ourselves
            if (isLDAPUserLocked(ldapUser, lockoutDuration)) {
                user.setEnabled(false);
                return true;
            } else {
                user.setEnabled(true);
                return false;
            }
        }

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

    public static boolean isLDAPUserLocked(LDAPObject ldapUser, long lockoutDuration) {
        DateTimeFormatter ldapFormatter = DateTimeFormatter.ofPattern(LDAP_TIMESTAMP_FORMAT);
        String lockTimestamp = ldapUser.getAttributeAsString(LDAP_PPOLICY_LOCK_TIME);
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC"));

        if (lockTimestamp != null) {
            if (lockTimestamp.equals(LDAP_LOCKOUT_TIMESTAMP)) {
                return true;
            } else {
                ZonedDateTime lockedTime = ZonedDateTime.parse(lockTimestamp, ldapFormatter);

                if (lockoutDuration > 0) {
                    ZonedDateTime unlockedTime = lockedTime.plusSeconds(lockoutDuration);
                    // account is only locked within the lockout interval
                    return lockedTime.isBefore(now) && unlockedTime.isAfter(now);
                } else {
                    // lockoutDuration of 0 means the lockout is permanent until removed by the
                    // admin
                    return lockedTime.isBefore(now);
                }
            }
        }

        return false;
    }

    public class OpenLDAPUserModelDelegate extends TxAwareLDAPUserModelDelegate {

        private final LDAPObject ldapUser;

        public OpenLDAPUserModelDelegate(UserModel delegate, LDAPObject ldapUser) {
            super(delegate, ldapProvider, ldapUser);
            this.ldapUser = ldapUser;
        }

        @Override
        public boolean isEnabled() {
            long lockoutDuration = mapperModel.get(CONFIG_LDAP_LOCKOUT_DURATION, 0);
            return super.isEnabled() && !isLDAPUserLocked(ldapUser, lockoutDuration);
        }

        @Override
        public void setEnabled(boolean enabled) {
            super.setEnabled(enabled);
            long lockoutDuration = mapperModel.get(CONFIG_LDAP_LOCKOUT_DURATION, 0);

            if (!isLDAPUserLocked(ldapUser, lockoutDuration) != enabled) {
                if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {

                    if (enabled) {
                        ldapUser.setAttribute(LDAP_PPOLICY_LOCK_TIME, null);
                    } else {
                        ldapUser.setSingleAttribute(LDAP_PPOLICY_LOCK_TIME, LDAP_LOCKOUT_TIMESTAMP);
                    }

                    markUpdatedAttributeInTransaction(LDAPConstants.ENABLED);
                }
            }

        }

    }

}
