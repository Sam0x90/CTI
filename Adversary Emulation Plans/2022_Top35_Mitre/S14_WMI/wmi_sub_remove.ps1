# Remove the binding
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {
    $_.Filter -match 'NotepadStartFilter'
} | ForEach-Object { $_.Delete() }

# Remove the consumer
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {
    $_.Name -eq 'NotepadStartVBScriptConsumer'
} | ForEach-Object { $_.Delete() }

# Remove the filter
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object {
    $_.Name -eq 'NotepadStartFilter'
} | ForEach-Object { $_.Delete() }
