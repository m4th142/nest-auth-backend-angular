import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from "bcryptjs";

import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

import { JwtPaylod } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterDto } from './dto/register.dto';



@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
      private userModel: Model<User>,

      private jwtService: JwtService,
  ) {}



  async create(createUserDto: CreateUserDto): Promise<User> {
    console.log(createUserDto);

    
    try{

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

      await newUser.save();
      const { password:_, ...user } =  newUser.toJSON();

      return user;


    } catch (error) {
      if ( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } already exist!`)
      }
      throw new InternalServerErrorException('Something terrible happenen!')
    }


  }

  async register( registerDto:RegisterDto ) {

    const user = await this.create( registerDto )


    return {
      user: user,
      token:  this.getJwtToken({ id:user._id })
    }

  }


  async login(loginDto: LoginDto): Promise<LoginResponse> {


    const { password, email } = loginDto

    const user = await this.userModel.findOne({ email });

    if ( !user ) {
      throw new UnauthorizedException('Not valid credentials - email')
    }

    if ( !bcryptjs.compareSync( password, user.password ) ){
      throw new UnauthorizedException('Not valid credentials - password')
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken( { id: user.id } ),
    };
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id:string ) {
    const user = await this.userModel.findById(id);

    const { password, ...rest } = user.toJSON();

    return rest;

  }

  
  getJwtToken( paylod: JwtPaylod ){
    const token = this.jwtService.sign(paylod);
    return token; 
  }
  

  // checkToken() {
  //   const user = this.userModel.findOne();

  //   if ( !user ) {
  //     throw new UnauthorizedException();
  //   }

    // const { password:_, ...rest } = user.toJson


  // }



  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateAuthDto: UpdateAuthDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }
}
