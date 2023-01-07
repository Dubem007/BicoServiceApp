using Autofac;
using BicoAuthService.Interface;
using BicoAuthService.Services;
using System.Reflection;

namespace BicoAuthService.Helpers
{
    public class AutofacContainerModule : Autofac.Module
    {
        protected override void Load(ContainerBuilder builder)
        {
            builder.RegisterGeneric(typeof(Repository<>))
               .As(typeof(IRepository<>))
               .InstancePerLifetimeScope();
            //builder.RegisterType<TokenService>().As<IToken>()
            //   .InstancePerLifetimeScope();
            //builder.RegisterType<UserActivityService>().As<IUserActivityRepository>()
            //   .InstancePerLifetimeScope();
            //builder.RegisterType<UserRepository>().As<IUserRepository>()
            //  .InstancePerLifetimeScope();
            //builder.RegisterType<Authentication>().As<IAuthentication>()
            //  .InstancePerLifetimeScope();
            builder.RegisterAssemblyTypes(typeof(IAutoDependencyService).Assembly)
                .AssignableTo<IAutoDependencyService>()
                .As<IAutoDependencyService>()
                .AsImplementedInterfaces().InstancePerLifetimeScope();

            base.Load(builder);
        }
    }
}
