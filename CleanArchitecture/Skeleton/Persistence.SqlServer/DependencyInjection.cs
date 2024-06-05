using Microsoft.Extensions.DependencyInjection;

namespace Persistence.SqlServer;

public static class DependencyInjection
{
    public static IServiceCollection AddPersistenceSqlServer(this IServiceCollection services)
    {
        return services;
    }
}