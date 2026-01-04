from collections import List

fn parse_pem(pem_data: String) -> List[String]:
    var blocks = List[String]()
    var start_marker = "-----BEGIN"
    var end_marker = "-----END"
    
    var pos = 0
    while True:
        var start_pos = pem_data.find(start_marker, pos)
        if start_pos == -1:
            break
        
        # Find the end of the BEGIN line
        var begin_line_end = pem_data.find("-----", start_pos + len(start_marker))
        if begin_line_end == -1:
            break
        begin_line_end += 5
        
        var end_pos = pem_data.find(end_marker, begin_line_end)
        if end_pos == -1:
            break
            
        var block = pem_data[begin_line_end:end_pos]
        blocks.append(block)
        
        # Move past the END marker line
        var end_line_end = pem_data.find("-----", end_pos + len(end_marker))
        if end_line_end == -1:
            pos = end_pos + len(end_marker)
        else:
            pos = end_line_end + 5
            
    return blocks^
