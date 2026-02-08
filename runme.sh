dotnet run --project ELF-Inspector.csproj -- \
  --file samples/nano \
  --output report-nano.txt \
  --output-path samples


dotnet run --project ELF-Inspector.csproj -- \
  --file samples/busybox \
  --output report-busybox.txt \
  --output-path samples
