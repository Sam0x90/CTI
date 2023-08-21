
# Defining the query to target notepad.exe
$filterQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"

# Creating the filter that uses the specifed query
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = 'NotepadStartFilter'
    EventNamespace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = $filterQuery
}

# Create the consumer (action), in our case executing a vbs script
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = 'NotepadStartVBScriptConsumer'
    CommandLineTemplate = 'wscript.exe "C:\temp\cmd_fileping.vbs"'
}

# Create the binding between the event and the consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
