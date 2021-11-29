package solutions.seven.keycloak.openldap_ppolicy_mapper;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;

import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OpenLDAPppolicyMapperFactory extends AbstractLDAPStorageMapperFactory {

    public static final String PROVIDER_ID = "openldap_ppolicy_mapper";
    protected static final List<ProviderConfigProperty> configProperties;

    static {
        configProperties = getConfigProps(null);
    }

    private static List<ProviderConfigProperty> getConfigProps(ComponentModel parent) {
        return ProviderConfigurationBuilder.create().property().name(OpenLDAPppolicyMapper.CONFIG_LDAP_LOCKOUT_DURATION)
                .label("ppolicy pwdLockoutDuration")
                .helpText(
                        "Time in seconds the user is locked out of their account after a lockout incident. Set this to the value in pwdLockoutDuration. 0 means forever.")
                .type(ProviderConfigProperty.STRING_TYPE).defaultValue("0").add().build();

    }

    @Override
    public String getHelpText() {
        return "Mapper for OpenLDAP enities using the ppolicy to map the users enabled state to a pwdAccountLocked timestamp.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
        return getConfigProps(parent);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel,
            LDAPStorageProvider federationProvider) {
        return new OpenLDAPppolicyMapper(mapperModel, federationProvider);
    }
}
