/**
File Name : fairytale-board.dto
Description : 동화 스토리 보드 DTO
Author : 강민규

History
Date        Author      Status      Description
2024.07.22  강민규      Created     
2024.07.22  강민규      Modified    based on create dto
*/

import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsString, IsNotEmpty, IsBoolean } from 'class-validator';

export class BoardFairytaleDto {
    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    title: string;

    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    theme: '우화' | '환경' | '사랑' | '모험' | '추리' | '기타';

    @ApiProperty()
    @IsNotEmpty()
    content: string;

    @ApiProperty()
    @IsBoolean()
    @Transform(({ value }) => value === 'true' || value === true)
    privatedAt: boolean;
}
