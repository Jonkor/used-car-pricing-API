import { BadRequestException, Injectable } from '@nestjs/common';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';
import { QueryFailedError } from 'typeorm';
import { UsersService } from './users.service';

const scrypt = promisify(_scrypt);

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async signup(email: string, password: string) {
    const salt = randomBytes(8).toString('hex');
    const hash = (await scrypt(password, salt, 32)) as Buffer;
    const passwordHash = `${salt}.${hash.toString('hex')}`;

    try {
      return await this.usersService.create(email, passwordHash);
    } catch (error) {
      if (this.isDuplicateEmailError(error)) { // Check if email exists
        throw new BadRequestException('email in use');
      }

      throw error;
    }
  }

  signin(email: string, password: string) {
    void email;
    void password;
  }

  private isDuplicateEmailError(error: unknown): boolean {
    if (!(error instanceof QueryFailedError)) {
      return false;
    }

    const driverError = error.driverError as {
      code?: string;
      message?: string;
    };

    return (
      driverError.code === 'SQLITE_CONSTRAINT_UNIQUE' ||
      (driverError.code === 'SQLITE_CONSTRAINT' &&
        driverError.message?.includes('user.email') === true)
    );
  }
}
