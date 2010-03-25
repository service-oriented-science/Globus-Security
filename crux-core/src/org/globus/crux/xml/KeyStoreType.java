//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-833 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2010.03.01 at 12:39:11 PM CST 
//


package org.globus.crux.xml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for keyStoreType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="keyStoreType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="keyStorePath" type="{http://www.globus.org/security/descriptor/container}valStringType"/>
 *         &lt;element name="keyStorePass" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="keyStoreAlias" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *       &lt;attribute name="type" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "keyStoreType", propOrder = {
    "keyStorePath",
    "keyStorePass",
    "keyStoreAlias"
})
public class KeyStoreType {

    @XmlElement(required = true)
    protected ValStringType keyStorePath;
    @XmlElement(required = true)
    protected String keyStorePass;
    @XmlElement(required = true)
    protected String keyStoreAlias;
    @XmlAttribute
    protected String type;

    /**
     * Gets the value of the keyStorePath property.
     * 
     * @return
     *     possible object is
     *     {@link ValStringType }
     *     
     */
    public ValStringType getKeyStorePath() {
        return keyStorePath;
    }

    /**
     * Sets the value of the keyStorePath property.
     * 
     * @param value
     *     allowed object is
     *     {@link ValStringType }
     *     
     */
    public void setKeyStorePath(ValStringType value) {
        this.keyStorePath = value;
    }

    /**
     * Gets the value of the keyStorePass property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyStorePass() {
        return keyStorePass;
    }

    /**
     * Sets the value of the keyStorePass property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyStorePass(String value) {
        this.keyStorePass = value;
    }

    /**
     * Gets the value of the keyStoreAlias property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyStoreAlias() {
        return keyStoreAlias;
    }

    /**
     * Sets the value of the keyStoreAlias property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyStoreAlias(String value) {
        this.keyStoreAlias = value;
    }

    /**
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setType(String value) {
        this.type = value;
    }

}
