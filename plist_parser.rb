# PropertyList XML File Parser
# 2009, Otto Linnemann

require 'rexml/document'
include REXML

class PropertyParser
  
  private
  
  # Base Element with pointer to parent
  # element and dynamic content
  class PTreeBase
    
    attr_accessor :obj, :parent  
    
    def initialize( obj, parent = nil )
      @obj = obj
      @parent = parent  
    end  
           
  end
  
  
  # PList Dictionary object which is mapped to a Ruby hash
  class PTreeArray < PTreeBase
      
    def initialize( parent )   
      super( Array.new, parent )    
    end    
    
    def store_value( value )
      @obj << value
    end
    
  end
  
  
  # PList Dictionary object which is mapped to a Ruby hash
  class PTreeDict < PTreeBase
       
    def initialize( parent )   
      super( Hash.new, parent )
    end    
        
  end

    
  # PList KeyValue singleton object which is mapped to a Ruby hash
  # parent must be a PTreeDict object
  class PTreeKeyValue < PTreeBase
    
    def initialize( parent )   
      raise "wrong element eror" if ! parent.is_a?( PTreeDict )
      super( Hash.new, parent )
      @key    = nil
      @value  = nil    
    end    
     
    def store_key( string )
      raise "wrong element eror" if ! string.is_a?( String )
      @key = string
    end
    
    def store_value( value )
      @value = value
      @obj[@key] = value
      self.parent.obj[@key] = value
    end
  
  end
  
  
  def tabs
    tabstr = ""
    i=0; while( i < @level ) do tabstr << "\t"; i+=1; end
    tabstr
  end
  
  
  # logging function for debugging purposes
  def log( str )
    # puts str
  end
  
  
  
  public
 
  # intializes parse object
  def initialize()
    @root     = nil
    @top      = nil
     
    @tag      = ""    
    @state    = :idle
    @level    = 0  
  end
  
  
  def parse( xmldata )
      Document.parse_stream( xmldata, self )
      to_a
  end
  
  
  # delivers to level parsing result as array
  def to_a
    @root.obj
  end
  


  def tag_start( name, attributes )
    log tabs + "> tagstart(" + name + " attr: " + attributes.to_s + ")"
    @tag = name
    
    case @tag
      when "plist"
        # for the DOM root element a create new instance is created
        @root = PTreeArray.new( nil )
        @top  = @root
    
      when "dict"
        @top = PTreeDict.new( @top )
        
      when "array"
        @top = PTreeArray.new( @top )
        
      when "key"
        @top = PTreeKeyValue.new( @top )
        
    end   

    @state = :tag_start
    @level += 1
  end
  
  
  def text( str )
    
    if @state != :tag_start
      @state = :text
      return
    end
          
    text = if( str.length > 3 ) then str else "" end
    log tabs + "> text(" + text + ")"
        
    case @tag
    
      when "key"
        @top.store_key( str )
         
      when "string"
        @top.store_value( str ) 
      
      when "integer"
        @top.store_value( str.to_i )

      when "real"
        @top.store_value( str.to_f )
      
    end

  @state = :text
    
  end
  
  
  def tag_end( name )
    @tag = name
    
    case @tag
      when "plist"
        raise "parse error empty object"  if @top.obj.empty?
        @top = @top.parent
      
      when "dict", "array"
        raise "parse error empty object"  if @top.obj.empty?
        @top.parent.store_value( @top.obj )
        @top = @top.parent
        @top = @top.parent if( @top.is_a? PTreeKeyValue )
                
      when "string", "integer", "real"
        @top = @top.parent if( @top.is_a? PTreeKeyValue )
    end
    
    @level -= 1
    log tabs + "> tag_end(" + name + ")"
    @state = :tag_end
  end
  
  
  def xmldecl( version, encoding, options )
    log tabs + ">>>> xmldecl(" + version + ", " + encoding + ", " + options.to_s + ")"
  end
  
  
  def doctype( type, scope, manufacturer, options )
    log tabs + ">>>>> doctype(" + type.to_s + ", " + scope.to_s + ", " + manufacturer.to_s + ", " + options.to_s + ")"
  end

  
end


# Sample invocation

=begin
prop = PropertyParser.new
data = ""
File.open("Info.plist", "r" ) { |fp| data = fp.read }
Document.parse_stream( data, prop )
log prop.to_a

data = ""
File.open("Info.plist", "r" ) { |fp| data = fp.read }
collection  = PropertyParser.new.parse( data )
puts collection

=end


__END__