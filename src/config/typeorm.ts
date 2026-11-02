import { DataSource } from 'typeorm';
import { getConfig } from './index';

const config = getConfig();

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: config.db.host,
  port: config.db.port,
  username: config.db.username,
  password: config.db.password,
  database: config.db.database,
  synchronize: false,
  logging: config.nodeEnv === 'development',
  entities: [__dirname + '/../entity/**/*.ts'],
  migrations: [__dirname + '/../migrations/**/*.ts'],
  subscribers: [],
});
