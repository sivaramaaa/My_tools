import javax.swing.JOptionPane;
import java.io.*;
import javax.swing.JFrame; 

public class idalaunch  extends JFrame 
{
          public void  execute(String command) {

		String s = null;
		String result = "";

		try {
			Process p = Runtime.getRuntime().exec(command);
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));

			while ((s = stdInput.readLine()) != null) {
				result += s;
			}

		} catch (IOException e) {
			System.out.println("exception happened - here's what I know: ");
			JOptionPane.showMessageDialog(null, "Error" + e);
			System.exit(-1);
		}
		
	}


public static void main(String[] args) throws Exception 
   { 
        idalaunch obj = new idalaunch();      
	Object[] choices = { "32", "64" };
	Object defaultChoice = choices[0];
	int output = JOptionPane.showOptionDialog(null, "What do u want to launch ?", "launch",JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, choices, defaultChoice);
			if (output == JOptionPane.YES_OPTION) {
				obj.execute("wine  /root/Desktop/tools/IDA_Pro/idaq.exe ");
                                
			} else if (output == JOptionPane.NO_OPTION) {
				obj.execute("wine  /root/Desktop/tools/IDA_Pro/idaq64.exe ");
                            
			}
      System.exit(0);
   }

}
