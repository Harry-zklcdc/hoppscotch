import { UnauthorizedException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { mockDeep, mockReset } from 'jest-mock-extended'
import { UserService } from 'src/user/user.service'
import { AuthService } from '../auth.service'
import { OidcStrategy } from '../strategies/oidc.strategy'
import * as O from 'fp-ts/Option'
import * as E from 'fp-ts/Either'
import { AuthUser } from 'src/types/AuthUser'
import { AUTH_EMAIL_NOT_PROVIDED_BY_OAUTH } from 'src/errors'

const mockUserService = mockDeep<UserService>()
const mockAuthService = mockDeep<AuthService>()
const mockConfigService = mockDeep<ConfigService>()

const currentTime = new Date()

const user: AuthUser = {
  uid: '123344',
  email: 'dwight@dundermifflin.com',
  displayName: 'Dwight Schrute',
  photoURL: 'https://en.wikipedia.org/wiki/Dwight_Schrute',
  isAdmin: false,
  currentRESTSession: {},
  currentGQLSession: {},
  refreshToken: 'hbfvdkhjbvkdvdfjvbnkhjb',
  lastLoggedOn: currentTime,
  lastActiveOn: currentTime,
  createdOn: currentTime,
}

const oidcProfile = {
  id: 'oidc-user-123',
  displayName: 'Dwight Schrute',
  emails: [{ value: 'dwight@dundermifflin.com' }],
  photos: [{ value: 'https://en.wikipedia.org/wiki/Dwight_Schrute' }],
  provider: 'oidc',
}

beforeEach(() => {
  mockReset(mockUserService)
  mockReset(mockAuthService)
  mockReset(mockConfigService)
})

describe('OidcStrategy', () => {
  describe('initialization', () => {
    test('should initialize with issuer URL (discovery mode)', () => {
      mockConfigService.get.mockImplementation((key: string) => {
        const config: Record<string, string> = {
          'INFRA.OIDC_ISSUER_URL': 'https://accounts.example.com',
          'INFRA.OIDC_CLIENT_ID': 'client-id',
          'INFRA.OIDC_CLIENT_SECRET': 'client-secret',
          'INFRA.OIDC_CALLBACK_URL': 'https://app.example.com/auth/oidc/callback',
          'INFRA.OIDC_SCOPE': 'openid,profile,email',
        }
        return config[key]
      })

      const strategy = new OidcStrategy(
        mockUserService,
        mockAuthService,
        mockConfigService,
      )

      expect(strategy).toBeDefined()
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_ISSUER_URL')
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_CLIENT_ID')
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_CLIENT_SECRET')
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_CALLBACK_URL')
    })

    test('should initialize with manual endpoints when issuer URL is not provided', () => {
      mockConfigService.get.mockImplementation((key: string) => {
        const config: Record<string, string | undefined> = {
          'INFRA.OIDC_ISSUER_URL': undefined,
          'INFRA.OIDC_CLIENT_ID': 'client-id',
          'INFRA.OIDC_CLIENT_SECRET': 'client-secret',
          'INFRA.OIDC_CALLBACK_URL': 'https://app.example.com/auth/oidc/callback',
          'INFRA.OIDC_AUTHORIZATION_ENDPOINT': 'https://provider.com/authorize',
          'INFRA.OIDC_TOKEN_ENDPOINT': 'https://provider.com/token',
          'INFRA.OIDC_USERINFO_ENDPOINT': 'https://provider.com/userinfo',
        }
        return config[key]
      })

      const strategy = new OidcStrategy(
        mockUserService,
        mockAuthService,
        mockConfigService,
      )

      expect(strategy).toBeDefined()
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_AUTHORIZATION_ENDPOINT')
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_TOKEN_ENDPOINT')
      expect(mockConfigService.get).toHaveBeenCalledWith('INFRA.OIDC_USERINFO_ENDPOINT')
    })
  })

  describe('validate', () => {
    let strategy: OidcStrategy

    beforeEach(() => {
      mockConfigService.get.mockImplementation((key: string) => {
        const config: Record<string, string> = {
          'INFRA.OIDC_ISSUER_URL': 'https://accounts.example.com',
          'INFRA.OIDC_CLIENT_ID': 'client-id',
          'INFRA.OIDC_CLIENT_SECRET': 'client-secret',
          'INFRA.OIDC_CALLBACK_URL': 'https://app.example.com/auth/oidc/callback',
        }
        return config[key]
      })

      strategy = new OidcStrategy(
        mockUserService,
        mockAuthService,
        mockConfigService,
      )
    })

    test('should create new user when not found', async () => {
      mockUserService.findUserByEmail.mockResolvedValue(O.none)
      mockUserService.createUserSSO.mockResolvedValue(user)

      const result = await strategy.validate(
        {} as any,
        'https://accounts.example.com',
        oidcProfile,
        {},
        'id-token',
        'access-token',
        'refresh-token',
        jest.fn(),
      )

      expect(mockUserService.findUserByEmail).toHaveBeenCalledWith('dwight@dundermifflin.com')
      expect(mockUserService.createUserSSO).toHaveBeenCalledWith(
        'access-token',
        'refresh-token',
        {
          id: 'oidc-user-123',
          displayName: 'Dwight Schrute',
          emails: [{ value: 'dwight@dundermifflin.com' }],
          photos: [{ value: 'https://en.wikipedia.org/wiki/Dwight_Schrute' }],
          provider: 'OIDC',
        },
      )
      expect(result).toEqual(user)
    })

    test('should link to existing user with same email', async () => {
      const existingUser = {
        ...user,
        displayName: null,
        photoURL: null,
      }

      mockUserService.findUserByEmail.mockResolvedValue(O.some(existingUser))
      mockUserService.updateUserDetails.mockResolvedValue(E.right(user))
      mockAuthService.checkIfProviderAccountExists.mockResolvedValue(O.none)
      mockUserService.createProviderAccount.mockResolvedValue({
        id: 'account-123',
        userId: user.uid,
        provider: 'OIDC',
        providerAccountId: 'oidc-user-123',
        providerRefreshToken: 'refresh-token',
        providerAccessToken: 'access-token',
        providerScope: 'openid profile email',
        loggedIn: currentTime,
      })

      const result = await strategy.validate(
        {} as any,
        'https://accounts.example.com',
        oidcProfile,
        {},
        'id-token',
        'access-token',
        'refresh-token',
        jest.fn(),
      )

      expect(mockUserService.findUserByEmail).toHaveBeenCalledWith('dwight@dundermifflin.com')
      expect(mockUserService.updateUserDetails).toHaveBeenCalledWith(
        existingUser,
        {
          id: 'oidc-user-123',
          displayName: 'Dwight Schrute',
          emails: [{ value: 'dwight@dundermifflin.com' }],
          photos: [{ value: 'https://en.wikipedia.org/wiki/Dwight_Schrute' }],
          provider: 'OIDC',
        },
      )
      expect(mockAuthService.checkIfProviderAccountExists).toHaveBeenCalledWith(
        existingUser,
        {
          id: 'oidc-user-123',
          displayName: 'Dwight Schrute',
          emails: [{ value: 'dwight@dundermifflin.com' }],
          photos: [{ value: 'https://en.wikipedia.org/wiki/Dwight_Schrute' }],
          provider: 'OIDC',
        },
      )
      expect(mockUserService.createProviderAccount).toHaveBeenCalledWith(
        existingUser,
        'access-token',
        'refresh-token',
        {
          id: 'oidc-user-123',
          displayName: 'Dwight Schrute',
          emails: [{ value: 'dwight@dundermifflin.com' }],
          photos: [{ value: 'https://en.wikipedia.org/wiki/Dwight_Schrute' }],
          provider: 'OIDC',
        },
      )
      expect(result).toEqual(existingUser)
    })

    test('should return existing user when provider account already exists', async () => {
      mockUserService.findUserByEmail.mockResolvedValue(O.some(user))
      mockAuthService.checkIfProviderAccountExists.mockResolvedValue(
        O.some({
          id: 'account-123',
          userId: user.uid,
          provider: 'OIDC',
          providerAccountId: 'oidc-user-123',
          providerRefreshToken: 'refresh-token',
          providerAccessToken: 'access-token',
          providerScope: 'openid profile email',
          loggedIn: currentTime,
        }),
      )

      const result = await strategy.validate(
        {} as any,
        'https://accounts.example.com',
        oidcProfile,
        {},
        'id-token',
        'access-token',
        'refresh-token',
        jest.fn(),
      )

      expect(mockUserService.findUserByEmail).toHaveBeenCalledWith('dwight@dundermifflin.com')
      expect(mockAuthService.checkIfProviderAccountExists).toHaveBeenCalled()
      expect(mockUserService.createProviderAccount).not.toHaveBeenCalled()
      expect(result).toEqual(user)
    })

    test('should throw on invalid email (missing)', async () => {
      const profileWithoutEmail = {
        ...oidcProfile,
        emails: undefined,
      }

      await expect(
        strategy.validate(
          {} as any,
          'https://accounts.example.com',
          profileWithoutEmail,
          {},
          'id-token',
          'access-token',
          'refresh-token',
          jest.fn(),
        ),
      ).rejects.toThrow(UnauthorizedException)

      await expect(
        strategy.validate(
          {} as any,
          'https://accounts.example.com',
          profileWithoutEmail,
          {},
          'id-token',
          'access-token',
          'refresh-token',
          jest.fn(),
        ),
      ).rejects.toThrow(AUTH_EMAIL_NOT_PROVIDED_BY_OAUTH)
    })

    test('should throw on invalid email (empty)', async () => {
      const profileWithEmptyEmail = {
        ...oidcProfile,
        emails: [{ value: '' }],
      }

      await expect(
        strategy.validate(
          {} as any,
          'https://accounts.example.com',
          profileWithEmptyEmail,
          {},
          'id-token',
          'access-token',
          'refresh-token',
          jest.fn(),
        ),
      ).rejects.toThrow(UnauthorizedException)
    })

    test('should throw on invalid email format', async () => {
      const profileWithInvalidEmail = {
        ...oidcProfile,
        emails: [{ value: 'not-an-email' }],
      }

      await expect(
        strategy.validate(
          {} as any,
          'https://accounts.example.com',
          profileWithInvalidEmail,
          {},
          'id-token',
          'access-token',
          'refresh-token',
          jest.fn(),
        ),
      ).rejects.toThrow(UnauthorizedException)
    })

    test('should throw when updateUserDetails fails', async () => {
      const existingUser = {
        ...user,
        displayName: null,
        photoURL: null,
      }

      mockUserService.findUserByEmail.mockResolvedValue(O.some(existingUser))
      mockUserService.updateUserDetails.mockResolvedValue(E.left('user/not_found'))

      await expect(
        strategy.validate(
          {} as any,
          'https://accounts.example.com',
          oidcProfile,
          {},
          'id-token',
          'access-token',
          'refresh-token',
          jest.fn(),
        ),
      ).rejects.toThrow(UnauthorizedException)
    })
  })
})
