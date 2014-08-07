CREATE TABLE oauth_consumers (
  id serial,
  consumer_key varchar(255) NOT NULL,
  consumer_secret varchar(255) NOT NULL,
  consumer_type smallint NOT NULL DEFAULT 0, -- 0普通 1客户端
  active smallint NOT NULL,
  CONSTRAINT oauth_consumers_id_pkey PRIMARY KEY (id )
);

CREATE TABLE oauth_consumer_nonces (
  id serial,
  consumer_id integer NOT NULL,
  timestamp bigint NOT NULL,
  nonce varchar(255) NOT NULL,
  CONSTRAINT oauth_consumer_nonces_id_pkey PRIMARY KEY (id),
  CONSTRAINT oauth_consumer_nonces_consumer_key UNIQUE (consumer_id, timestamp, nonce)
);
CREATE INDEX oauth_consumer_nonces_consumer_id_key ON oauth_consumer_nonces USING btree (consumer_id);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  id serial,
  type integer NOT NULL,
  consumer_id integer NOT NULL,
  user_id integer NOT NULL,
  token varchar(255) NOT NULL,
  token_secret varchar(255) NOT NULL,
  callback_url varchar(255),
  verifier varchar(255) NOT NULL,
  expires integer NOT NULL DEFAULT 3600,
  created timestamp without time zone NOT NULL,
  CONSTRAINT oauth_tokens_id_pkey PRIMARY KEY (id)
);
CREATE INDEX oauth_tokens_consumer_id_key ON oauth_tokens USING btree (consumer_id);
CREATE INDEX oauth_tokens_user_id_key ON oauth_tokens USING btree (user_id);
CREATE INDEX oauth_tokens_type_key ON oauth_tokens USING btree (type);

ALTER TABLE oauth_consumer_nonces
  ADD CONSTRAINT oauth_consumer_nonces_consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES oauth_consumers(id) ON DELETE CASCADE;

ALTER TABLE oauth_tokens
  ADD CONSTRAINT consumer_id_fkey FOREIGN KEY (consumer_id) REFERENCES oauth_consumers (id) ON DELETE CASCADE;
