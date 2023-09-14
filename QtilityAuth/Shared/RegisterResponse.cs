using Microsoft.AspNetCore.Identity;

namespace QtilityAuth.Shared
{
    public class RegisterResponse
    {
        public RegisterResponse(bool succeeded, IEnumerable<IdentityError> error)
        {
            this.Succeeded = succeeded;
            this.Errors = error;
        }
        public bool Succeeded { get; set; }
        public IEnumerable<IdentityError> Errors { get; set; }
    }
}
