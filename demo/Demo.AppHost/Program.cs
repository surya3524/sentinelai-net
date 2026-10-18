var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.Demo_Agent>("support-agent")
    .WithExternalHttpEndpoints();

builder.AddProject<Projects.Demo_Api>("dataset-api")
    .WithExternalHttpEndpoints();

builder.Build().Run();
