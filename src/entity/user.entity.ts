import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { Role } from '../middleware/auth.middleware';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ length: 50 })
  username!: string;

  @Index({ unique: true })
  @Column({ length: 255 })
  email!: string;

  @Column({ length: 255 })
  passwordHash!: string;

  @Column({ length: 100 })
  fullName!: string;

  @Column({
    type: 'enum',
    enum: Role,
    default: Role.USER,
  })
  role!: Role;

  @Column({ type: 'text', nullable: true })
  phoneEncrypted?: string;

  @Column({ type: 'text', nullable: true })
  idCardEncrypted?: string;

  @Column({ type: 'text', nullable: true })
  bankCardEncrypted?: string;

  @Column({ type: 'boolean', default: false })
  isActive!: boolean;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt?: Date;

  @Column({ type: 'varchar', length: 45, nullable: true })
  lastLoginIp?: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
