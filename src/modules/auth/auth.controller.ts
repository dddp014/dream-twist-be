/**
File Name : auth.controller
Description : Auth Controller
Author : 박수정

History
Date        Author      Status      Description
2024.07.30  박수정      Created     
2024.07.30  박수정      Modified    Google 회원가입 및 로그인 기능 추가
2024.08.01  박수정      Modified    RefreshToken 검증 및 AccessToken 재발급 기능 추가
2024.08.07  박수정      Modified    Google Callback 관련 응답 코드 변경
2024.08.10  박수정      Modified    로그인 전 기능에 대한 Swagger 코드 추가
*/

import { Body, Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { ApiGetOperation, ApiPostOperation } from 'shared/utils/swagger.decorators';
import { AuthService } from 'src/modules/auth/auth.service';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    // Google 회원가입 및 로그인
    @ApiGetOperation({
        summary: 'Google 회원가입 및 로그인',
        successMessage: 'Google 로그인 페이지로 리다이렉트됩니다.',
    })
    @Get('google/login')
    @UseGuards(AuthGuard('google'))
    async googleAuth() {}

    // Google Callback
    @ApiGetOperation({
        summary: 'Google 로그인 Callback',
        successMessage: 'Google 로그인 후, 리다이렉트된 URL에서 토큰을 받습니다.',
    })
    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleAuthCallback(@Req() req, @Res() res): Promise<void> {
        const userDTO = {
            googleId: req.user.googleId,
            email: req.user.email,
            name: req.user.name,
        };

        const tokens = await this.authService.googleLogin(userDTO);

        res.redirect(`http://localhost:3000/#accessToken=${tokens.accessToken}&refreshToken=${tokens.refreshToken}`);
    }

    // RefreshToken 검증 및 AccessToken 재발급
    @ApiPostOperation({
        summary: 'AccessToken 재발급',
        successMessage: '새로운 AccessToken이 발급되었습니다.',
    })
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                refreshToken: { type: 'string', example: 'refresh-token-example' },
            },
            required: ['refreshToken'],
        },
    })
    @Post('regenerate-accesstoken')
    async regenerateAccesstoken(@Body('refreshToken') refreshToken: string): Promise<{ accessToken: string }> {
        return this.authService.regenerateAccessToken(refreshToken);
    }
}
