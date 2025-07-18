package icu.secnotes.test;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

import icu.secnotes.pojo.Person;

public class DeserializeTest {

    public static void main(String[] args) throws Exception {
        Person person = new Person();
        person.setName("歪果仁");
        person.setAge(3);

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("/Users/liujianping/Downloads/person_xxoo.ser"));
        oos.writeObject(person);
        oos.close();

    }

}
