# TimeLineGenerator
AD account timeline generator - parse DC security logs for activity timeline.


Can run directly on Domain Controllers (Live, through WinRM), OR - specify Path to Evtx files.

Can run a Full/Longer report, or a more Focused/Quicker one, with a select set of events to filter. default is "Focused-Quicker".

Can set the Max Events to fetch Per DC (limit to the last X events from the log, for performance). Default is to get all events.

Note: Work in progress - need to add Help, and some other 'touches'...
