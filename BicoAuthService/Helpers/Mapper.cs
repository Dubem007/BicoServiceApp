using AutoMapper;
using BicoAuthService.Entities.DataTransferObjects;
using BicoAuthService.Entities.Identity;

namespace BicoAuthService.Helpers
{
    public class Mapper : Profile
    {
        public Mapper()
        {
            CreateMap<UserLoginResponse, User>();
            CreateMap<User, UserLoginResponse>();
            CreateMap<UserMemberResponseDto, UserMemberCreationInputDto>();
            CreateMap<UserMemberCreationInputDto, UserMemberResponseDto>();
            CreateMap<UserMemberResponseDto, UserMemberUpdateInputDto>();
            CreateMap<UserMemberUpdateInputDto, UserMemberResponseDto>();
            CreateMap<GetSetPasswordDto, User>();
            CreateMap<User, GetSetPasswordDto>();
            CreateMap<GetInitialMemberTokenResponseDto, User>();
            CreateMap<User, GetInitialMemberTokenResponseDto>();
            CreateMap<UserMemberResponseDto, User>();
            CreateMap<User, UserMemberResponseDto>();
        }


    }
}
