-- spec 003: a data key is authenticated by a tag under the KEK's root - one planted by whoever could write the
-- store (wrapped with an RSA KEK's public key, say) has none that matches. Keys made before have none, and are
-- refused until `tresor-server rewrap` tags them.
ALTER TABLE data_keys ADD tag VARBINARY(MAX) NULL;
