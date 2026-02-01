import { Strategy } from 'passport-openidconnect';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as O from 'fp-ts/Option';
import { AuthService } from '../auth.service';
import * as E from 'fp-ts/Either';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { validateEmail } from 'src/utils';
import { AUTH_EMAIL_NOT_PROVIDED_BY_OAUTH } from 'src/errors';
import axios from 'axios';

async function fetchOidcConfiguration(issuerUrl: string) {
  try {
    const discoveryUrl = issuerUrl.endsWith('/.well-known/openid-configuration')
      ? issuerUrl
      : `${issuerUrl}/.well-known/openid-configuration`;
    
    const response = await axios.get(discoveryUrl, { timeout: 10000 });
    return {
      authorizationEndpoint: response.data.authorization_endpoint,
      tokenEndpoint: response.data.token_endpoint,
      userInfoEndpoint: response.data.userinfo_endpoint,
      issuer: response.data.issuer,
    };
  } catch (error) {
    console.error('Failed to fetch OIDC configuration:', error.message);
    return null;
  }
}

@Injectable()
export class OidcStrategy extends PassportStrategy(Strategy, 'oidc') {
  constructor(
    private usersService: UserService,
    private authService: AuthService,
    private configService: ConfigService,
  ) {
    const issuerUrl = configService.get<string>('INFRA.OIDC_ISSUER_URL');
    const manualAuthorizationURL = configService.get<string>(
      'INFRA.OIDC_AUTHORIZATION_ENDPOINT',
    );
    const manualTokenURL = configService.get<string>('INFRA.OIDC_TOKEN_ENDPOINT');
    const manualUserInfoURL = configService.get<string>(
      'INFRA.OIDC_USERINFO_ENDPOINT',
    );

    super({
      issuer: issuerUrl || 'https://placeholder.example.com',
      authorizationURL: manualAuthorizationURL || 'https://placeholder.example.com/authorize',
      tokenURL: manualTokenURL || 'https://placeholder.example.com/token',
      userInfoURL: manualUserInfoURL || 'https://placeholder.example.com/userinfo',
      clientID: configService.get<string>('INFRA.OIDC_CLIENT_ID'),
      clientSecret: configService.get<string>('INFRA.OIDC_CLIENT_SECRET'),
      callbackURL: configService.get<string>('INFRA.OIDC_CALLBACK_URL'),
      scope: configService.get<string>('INFRA.OIDC_SCOPE')?.split(',') ?? [
        'openid',
        'profile',
        'email',
      ],
      passReqToCallback: true,
    });

    // Fetch OIDC configuration asynchronously and update strategy
    if (issuerUrl && !manualAuthorizationURL) {
      fetchOidcConfiguration(issuerUrl).then((config) => {
        if (config) {
          // Update OAuth2 client with discovered endpoints
          (this as any)._oauth2._authorizeUrl = config.authorizationEndpoint;
          (this as any)._oauth2._accessTokenUrl = config.tokenEndpoint;
          (this as any)._userInfoURL = config.userInfoEndpoint;
          (this as any)._issuer = config.issuer;
          console.log('OIDC configuration loaded from discovery endpoint');
        }
      });
    }
  }

  async validate(
    req: Request,
    issuer: string,
    profile: {
      id: string
      displayName?: string
      emails?: Array<{ value: string }>
      photos?: Array<{ value: string }>
      provider?: string
    },
    context: unknown,
    idToken: string,
    accessToken: string,
    refreshToken: string,
  ) {
    // Extract email from profile - OIDC providers may structure this differently
    const email = profile.emails?.[0]?.value

    if (!validateEmail(email))
      throw new UnauthorizedException(AUTH_EMAIL_NOT_PROVIDED_BY_OAUTH)

    // Normalize profile to match expected format for UserService
    const normalizedProfile = {
      id: profile.id,
      displayName: profile.displayName,
      emails: profile.emails,
      photos: profile.photos,
      provider: 'OIDC',
    }

    const user = await this.usersService.findUserByEmail(email)

    if (O.isNone(user)) {
      const createdUser = await this.usersService.createUserSSO(
        accessToken,
        refreshToken,
        normalizedProfile,
      )
      return createdUser
    }

    /**
     * displayName and photoURL maybe null if user logged-in via magic-link before SSO
     */
    if (!user.value.displayName || !user.value.photoURL) {
      const updatedUser = await this.usersService.updateUserDetails(
        user.value,
        normalizedProfile,
      )
      if (E.isLeft(updatedUser)) {
        throw new UnauthorizedException(updatedUser.left)
      }
    }

    /**
     * Check to see if entry for OIDC is present in the Account table for user
     * If user was created with another provider findUserByEmail may return true
     */
    const providerAccountExists =
      await this.authService.checkIfProviderAccountExists(
        user.value,
        normalizedProfile,
      )

    if (O.isNone(providerAccountExists))
      await this.usersService.createProviderAccount(
        user.value,
        accessToken,
        refreshToken,
        normalizedProfile,
      )

    return user.value
  }
}
