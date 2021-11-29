# Keycloak OpenLDAP ppolicy mapper

This is a plugin for the authentication provider [keycloak](https://keycloak.org). It maps the keycloak account state to OpenLDAP ppolicy attributes.

## Deploy from source

1. To deploy from source, you must first build the plugin. You can use Maven to do so: `mvn clean package`.
2. Copy the target (from the `target` folder) into the `deployments` folder of your keycloak installation. (Typically: `/opt/keycloak/deployments`)

TODO
