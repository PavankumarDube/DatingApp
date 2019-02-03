using System.ComponentModel.DataAnnotations;

namespace DatingApp.API.Dtos
{
    public class UserForRegisterDtos
    {
        [Required]
        public string Username {get; set;}

        [Required]
        [StringLength(8, MinimumLength = 4,  ErrorMessage ="You must specify password between four and eight charactors")]
        public string Password {get; set;}

    }
}