# Embed CA, certificate & key directly into binary
idf_component_register(SRCS "nebraska_example_main.c"
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES certs/fake_ca.pem certs/fake_client.crt certs/fake_client.key)
