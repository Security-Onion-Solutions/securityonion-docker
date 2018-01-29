module SecurityOnion;

@load ./interface
@load base/frameworks/input

export {

    global sensorname = "";

	type Idx: record {
	        interface: string;
	};

	type Val: record {
        	sensorname: string;
	};

	global sensornames: table[string] of Val = table();

}

event bro_init() &priority=5
    {
	Input::add_table([$source="/etc/nsm/sensortab.bro", $name="sensornames", $idx=Idx, $val=Val, $destination=sensornames]);
	Input::remove("sensornames");
    }   
