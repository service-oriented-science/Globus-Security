import org.slf4j.bridge.SLF4JBridgeHandler

SLF4JBridgeHandler.install()


builder = new org.rzo.yajsw.groovy.WrapperBuilder()
builder.'wrapper.java.app.jar' = 'start.jar'
builder.'wrapper.java.classpath.1' = 'start.jar'
builder.'wrapper.java.classpath.2' = 'lib/*.jar'
cruxService = builder.service()
cruxService.start()



/*wrapper.working.dir=.

wrapper.exit_on_main_terminate = -1 
wrapper.java.app.jar=start.jar
wrapper.java.classpath.1=start.jar
wrapper.java.classpath.2=lib/*.jar
wrapper.java.additional.1=-Dlogback.configurationFile=etc/config.xml
wrapper.java.additional.2=-Dcom.sun.management.jmxremote
wrapper.java.initmemory=128
wrapper.logfile=log/crux-log.txt
wrapper.console.loglevel=WARN
wrapper.jvm.port=21543
wrapper.java.maxmemory=256
wrapper.java.jmx=true

wrapper.ntservice.name=Globus Crux
wrapper.ntservice.displayname=Globus Crux
wrapper.ntservice.description=Globus Crux is a toolkit and server for building and deploying secure Grid Services.
wrapper.ntservice.starttype=AUTO_START
wrapper.ntservice.interactive=false*/
