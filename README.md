# Input Filter
An experimental WinAPI app. Shows green if your last mouse input was made by you. Otherwise shows red (inputs by the virtual devices or software)
# Methods
[*] LLMHF_INJECTED flag check in the mouse event - basic filtering for software inputs
[*] Comparing mouse events to RawInput events - a better filtering option
[*] Checking for the virtual Generic HIDs by their properties