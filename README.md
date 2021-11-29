# Keycloak OpenLDAP ppolicy mapper

This is a plugin for the authentication provider [keycloak](https://keycloak.org). It maps the keycloak user's disabled state to the ppolicy `pwdAccountLockedTime` attribute. To properly work, the time set as `pwdLockoutDuration` in the password policy of the affected records should be set in the mapper settings.

**Warning:** This provider relies on private SPIs which may change at any point without notice. Please test the provider before you update your production deployment.

## Features

- Manually enable/disable users in OpenLDAP from Keycloak
- Disable users for the lockout duration if the password policy mandates it (e.g. too many dailed attempts)

## Deploy from source

1. To deploy from source, you must first build the plugin. You can use Maven to do so: `mvn clean package`.
2. Copy the target (from the `target` folder) into the `deployments` folder of your keycloak installation. (Typically: `/opt/keycloak/standalone/deployments`)
