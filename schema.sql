DROP TABLE IF EXISTS attending CASCADE;

CREATE TABLE attending (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  game_id INTEGER REFERENCES games(game_id)
);
DROP TABLE IF EXISTS locations CASCADE;

CREATE TABLE locations (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255),
  lat DECIMAL(12,8),
  lon DECIMAL(12,8)
);

DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(40),
  username VARCHAR(20),
  avatar VARCHAR(4)
);

DROP TABLE IF EXISTS games CASCADE;

CREATE TABLE games (
  game_id SERIAL PRIMARY KEY,
  user_id VARCHAR(40),
  game_name VARCHAR(40),  
  location INTEGER REFERENCES locations(id),
  time TIME,
  date VARCHAR(20),
  skill_level VARCHAR(12),
  players_wanted SMALLINT,
  description VARCHAR(255)
);

