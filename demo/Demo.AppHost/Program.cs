var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.Demo_Agent>("support-agent")
    .WithExternalHttpEndpoints();

builder.Build().Run();
