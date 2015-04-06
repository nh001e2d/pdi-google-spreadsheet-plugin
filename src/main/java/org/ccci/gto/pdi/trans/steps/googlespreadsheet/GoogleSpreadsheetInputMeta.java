package org.ccci.gto.pdi.trans.steps.googlespreadsheet;

import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.TableItem;
import org.pentaho.di.core.CheckResult;
import org.pentaho.di.core.CheckResultInterface;
import org.pentaho.di.core.Const;
import org.pentaho.di.core.annotations.Step;
import org.pentaho.di.core.database.DatabaseMeta;
import org.pentaho.di.core.exception.KettleException;
import org.pentaho.di.core.exception.KettleStepException;
import org.pentaho.di.core.exception.KettleValueException;
import org.pentaho.di.core.exception.KettleXMLException;
import org.pentaho.di.core.row.RowMetaInterface;
import org.pentaho.di.core.row.ValueMeta;
import org.pentaho.di.core.row.ValueMetaInterface;
import org.pentaho.di.core.row.value.ValueMetaFactory;
import org.pentaho.di.core.variables.VariableSpace;
import org.pentaho.di.core.xml.XMLHandler;
import org.pentaho.di.repository.ObjectId;
import org.pentaho.di.repository.Repository;
import org.pentaho.di.trans.Trans;
import org.pentaho.di.trans.TransMeta;
import org.pentaho.di.trans.step.*;
import org.pentaho.di.trans.steps.csvinput.CsvInputMeta;
import org.pentaho.di.trans.steps.textfileinput.TextFileInputField;
import org.pentaho.metastore.api.IMetaStore;
import org.w3c.dom.Node;

import com.google.gdata.client.Query;
import com.google.gdata.client.spreadsheet.FeedURLFactory;
import com.google.gdata.client.spreadsheet.SpreadsheetService;
import com.google.gdata.data.spreadsheet.ListEntry;
import com.google.gdata.data.spreadsheet.ListFeed;
import com.google.gdata.util.ServiceException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyStore;
import java.util.List;

@Step(id = "GoogleSpreadsheetInput", image = "google-spreadsheet-input.png", name = "Google Spreadsheet Input",
        description = "Reads from a Google Spreadsheet", categoryDescription = "Input")
public class GoogleSpreadsheetInputMeta extends BaseStepMeta implements StepMetaInterface {
    private static Class<?> PKG = GoogleSpreadsheetInputMeta.class;

    private String serviceEmail;
    private String pkcsFilename;
    private KeyStore privateKeyStore;
    private String spreadsheetKey;
    private String worksheetId;
    private TextFileInputField[] inputFields;

    public GoogleSpreadsheetInputMeta() {
        super();
        allocate(0);
    }

    @Override
    public void setDefault() {
        this.serviceEmail = "";
        this.pkcsFilename = "";
        this.spreadsheetKey = "";
        this.worksheetId = "od6";
        this.privateKeyStore = null;

        TextFileInputField field = new TextFileInputField();
        field.setName("field");
        field.setType(ValueMetaInterface.TYPE_STRING);

        inputFields = new TextFileInputField[]{
                field,
        };
    }

    @Override
    public String getDialogClassName() {
        return "org.ccci.gto.pdi.ui.trans.steps.googlespreadsheet.GoogleSpreadsheetInputDialog";
    }

    public void allocate(int nrFields) {
        inputFields = new TextFileInputField[nrFields];
    }

    public String getServiceEmail() {
        return this.serviceEmail == null ? "" : this.serviceEmail;
    }

    public void setServiceEmail(String serviceEmail) {
        this.serviceEmail = serviceEmail;
    }

    public KeyStore getPrivateKeyStore() {
        return this.privateKeyStore;
    }

    public void setPrivateKeyStore(KeyStore pks) {
        this.privateKeyStore = pks;
    }

    public String getSpreadsheetKey() {
        return this.spreadsheetKey == null ? "" : this.spreadsheetKey;
    }

    public void setSpreadsheetKey(String key) {
        this.spreadsheetKey = key;
    }

    public String getWorksheetId() {
        return this.worksheetId == null ? "" : this.worksheetId;
    }

    public void setWorksheetId(String id) {
        this.worksheetId = id;
    }

    public String getPkcsFilename() {
		return pkcsFilename;
	}

	public void setPkcsFilename(String pkcsFilename) {
		this.pkcsFilename = pkcsFilename;
	}

	public TextFileInputField[] getInputFields() {
        return inputFields;
    }

    public void setInputFields(TextFileInputField[] inputFields) {
        this.inputFields = inputFields;
    }
    
    public boolean isDefaultFields() {
    	return inputFields == null || inputFields.length == 0
    			||  "field".equals(inputFields[0].getName())
    			|| "".equals(inputFields[0].getName());
    }
    
    public void retrieveFields(SpreadsheetService service, String spreadsheetKey, String worksheetId) throws IOException, ServiceException {
    	Query feedQuery = new Query(FeedURLFactory.getDefault().getListFeedUrl(spreadsheetKey, worksheetId, "private", "full"));
        feedQuery.setMaxResults(1);
        ListFeed feed = service.getFeed(feedQuery, ListFeed.class);
        List<ListEntry> rows = feed.getEntries();
        ListEntry row = rows.get(0);
        
        allocate(row.getCustomElements().getTags().size());

        int index = 0;
        for (String tag : row.getCustomElements().getTags()) {
            inputFields[index] = new TextFileInputField();
            inputFields[index].setName(Const.trim(tag));
            inputFields[index].setType(ValueMetaInterface.TYPE_STRING);
            index++;
        }
    }

    @Override
    public Object clone() {
        GoogleSpreadsheetInputMeta retval = (GoogleSpreadsheetInputMeta) super.clone();
        retval.setServiceEmail(this.serviceEmail);
        retval.setPkcsFilename(this.pkcsFilename);
        retval.setPrivateKeyStore(this.privateKeyStore);
        retval.setSpreadsheetKey(this.spreadsheetKey);
        retval.setWorksheetId(this.worksheetId);
        return retval;
    }

    @Override
    public String getXML() throws KettleException {
        StringBuilder xml = new StringBuilder();
        try {
            xml.append(XMLHandler.addTagValue("serviceEmail", this.serviceEmail));
            xml.append(XMLHandler.addTagValue("spreadsheetKey", this.spreadsheetKey));
            xml.append(XMLHandler.addTagValue("worksheetId", this.worksheetId));
            xml.append(XMLHandler.addTagValue("pkcs_filename", this.pkcsFilename));
            xml.append(XMLHandler.openTag("privateKeyStore"));
            xml.append(XMLHandler.buildCDATA(GoogleSpreadsheet.base64EncodePrivateKeyStore(this.privateKeyStore)));
            xml.append(XMLHandler.closeTag("privateKeyStore"));

            xml.append(XMLHandler.openTag("fields"));
            for (TextFileInputField field : inputFields) {
                xml.append(XMLHandler.openTag("field"));
                xml.append(XMLHandler.addTagValue("field_name", field.getName()));
                xml.append(XMLHandler.addTagValue("field_type", ValueMeta.getTypeDesc(field.getType())));
                xml.append(XMLHandler.addTagValue("field_format", field.getFormat()));
                xml.append(XMLHandler.addTagValue("field_currency", field.getCurrencySymbol()));
                xml.append(XMLHandler.addTagValue("field_decimal", field.getDecimalSymbol()));
                xml.append(XMLHandler.addTagValue("field_group", field.getGroupSymbol()));
                xml.append(XMLHandler.addTagValue("field_length", field.getLength()));
                xml.append(XMLHandler.addTagValue("field_precision", field.getPrecision()));
                xml.append(XMLHandler.addTagValue("field_trim_type", ValueMeta.getTrimTypeCode(field.getTrimType())));
                xml.append(XMLHandler.closeTag("field"));
            }
            xml.append(XMLHandler.closeTag("fields"));

        } catch (Exception e) {
            throw new KettleValueException("Unable to write step to XML", e);
        }
        return xml.toString();
    }

    @Override
    public void loadXML(Node stepnode, List<DatabaseMeta> databases, IMetaStore metaStore) throws KettleXMLException {
        try {
            this.serviceEmail = XMLHandler.getTagValue(stepnode, "serviceEmail");
            this.spreadsheetKey = XMLHandler.getTagValue(stepnode, "spreadsheetKey");
            this.worksheetId = XMLHandler.getTagValue(stepnode, "worksheetId");
            this.pkcsFilename = XMLHandler.getTagValue(stepnode, "pkcs_filename");
            this.privateKeyStore = GoogleSpreadsheet.base64DecodePrivateKeyStore(XMLHandler.getTagValue(stepnode, "privateKeyStore"));

            Node fields = XMLHandler.getSubNode(stepnode, "fields");
            int nrfields = XMLHandler.countNodes(fields, "field");

            allocate(nrfields);

            for (int i = 0; i < nrfields; i++) {
                inputFields[i] = new TextFileInputField();

                Node fnode = XMLHandler.getSubNodeByNr(fields, "field", i);

                inputFields[i].setName(XMLHandler.getTagValue(fnode, "field_name"));
                inputFields[i].setType(ValueMeta.getType(XMLHandler.getTagValue(fnode, "field_type")));
                inputFields[i].setFormat(XMLHandler.getTagValue(fnode, "field_format"));
                inputFields[i].setCurrencySymbol(XMLHandler.getTagValue(fnode, "field_currency"));
                inputFields[i].setDecimalSymbol(XMLHandler.getTagValue(fnode, "field_decimal"));
                inputFields[i].setGroupSymbol(XMLHandler.getTagValue(fnode, "field_group"));
                inputFields[i].setLength(Const.toInt(XMLHandler.getTagValue(fnode, "field_length"), -1));
                inputFields[i].setPrecision(Const.toInt(XMLHandler.getTagValue(fnode, "field_precision"), -1));
                inputFields[i].setTrimType(ValueMeta.getTrimTypeByCode(XMLHandler.getTagValue(fnode, "field_trim_type")));
            }

        } catch (Exception e) {
            throw new KettleXMLException("Unable to load step from XML", e);
        }
    }

    @Override
    public void readRep(Repository rep, IMetaStore metaStore, ObjectId id_step, List<DatabaseMeta> databases) throws KettleException {
        try {
            this.serviceEmail = rep.getStepAttributeString(id_step, "serviceEmail");
            this.spreadsheetKey = rep.getStepAttributeString(id_step, "spreadsheetKey");
            this.worksheetId = rep.getStepAttributeString(id_step, "worksheetId");
            this.pkcsFilename = rep.getStepAttributeString(id_step, "pkcs_filename");
            this.privateKeyStore = GoogleSpreadsheet.base64DecodePrivateKeyStore(rep.getStepAttributeString(id_step, "privateKeyStore"));

            int nrfields = rep.countNrStepAttributes(id_step, "field_name");

            allocate(nrfields);

            for (int i = 0; i < nrfields; i++) {
                inputFields[i] = new TextFileInputField();

                inputFields[i].setName(rep.getStepAttributeString(id_step, i, "field_name"));
                inputFields[i].setType(ValueMeta.getType(rep.getStepAttributeString(id_step, i, "field_type")));
                inputFields[i].setFormat(rep.getStepAttributeString(id_step, i, "field_format"));
                inputFields[i].setCurrencySymbol(rep.getStepAttributeString(id_step, i, "field_currency"));
                inputFields[i].setDecimalSymbol(rep.getStepAttributeString(id_step, i, "field_decimal"));
                inputFields[i].setGroupSymbol(rep.getStepAttributeString(id_step, i, "field_group"));
                inputFields[i].setLength((int) rep.getStepAttributeInteger(id_step, i, "field_length"));
                inputFields[i].setPrecision((int) rep.getStepAttributeInteger(id_step, i, "field_precision"));
                inputFields[i].setTrimType(ValueMeta.getTrimTypeByCode(rep.getStepAttributeString(id_step, i, "field_trim_type")));
            }
        } catch (Exception e) {
            throw new KettleException("Unexpected error reading step information from the repository", e);
        }
    }

    @Override
    public void saveRep(Repository rep, IMetaStore metaStore, ObjectId id_transformation, ObjectId id_step) throws KettleException {
        try {
            rep.saveStepAttribute(id_transformation, id_step, "serviceEmail", this.serviceEmail);
            rep.saveStepAttribute(id_transformation, id_step, "spreadsheetKey", this.spreadsheetKey);
            rep.saveStepAttribute(id_transformation, id_step, "worksheetId", this.worksheetId);
            rep.saveStepAttribute(id_transformation, id_step, "pkcs_filename", this.pkcsFilename);
            rep.saveStepAttribute(id_transformation, id_step, "privateKeyStore", GoogleSpreadsheet.base64EncodePrivateKeyStore(this.privateKeyStore));

            for (int i = 0; i < inputFields.length; i++) {
                TextFileInputField field = inputFields[i];

                rep.saveStepAttribute(id_transformation, id_step, i, "field_name", field.getName());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_type", ValueMeta.getTypeDesc(field.getType()));
                rep.saveStepAttribute(id_transformation, id_step, i, "field_format", field.getFormat());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_currency", field.getCurrencySymbol());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_decimal", field.getDecimalSymbol());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_group", field.getGroupSymbol());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_length", field.getLength());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_precision", field.getPrecision());
                rep.saveStepAttribute(id_transformation, id_step, i, "field_trim_type", ValueMeta.getTrimTypeCode(field.getTrimType()));
            }

        } catch (Exception e) {
            throw new KettleException("Unable to save step information to the repository for id_step=" + id_step, e);
        }
    }

    @Override
    public void getFields(RowMetaInterface inputRowMeta, String name, RowMetaInterface[] info, StepMeta nextStep, VariableSpace space, Repository repository, IMetaStore metaStore) throws KettleStepException {
        try {
            inputRowMeta.clear(); // Start with a clean slate, eats the input

            for (TextFileInputField field : inputFields) {
                ValueMetaInterface valueMeta = ValueMetaFactory.createValueMeta(field.getName(), field.getType());
                valueMeta.setConversionMask(field.getFormat());
                valueMeta.setLength(field.getLength());
                valueMeta.setPrecision(field.getPrecision());
                valueMeta.setConversionMask(field.getFormat());
                valueMeta.setDecimalSymbol(field.getDecimalSymbol());
                valueMeta.setGroupingSymbol(field.getGroupSymbol());
                valueMeta.setCurrencySymbol(field.getCurrencySymbol());
                valueMeta.setTrimType(field.getTrimType());
                valueMeta.setStorageType(ValueMetaInterface.STORAGE_TYPE_BINARY_STRING);
                valueMeta.setDateFormatLenient(true);
                valueMeta.setStringEncoding("UTF-8");

                ValueMetaInterface storageMetadata = ValueMetaFactory.cloneValueMeta(valueMeta, ValueMetaInterface.TYPE_STRING);
                storageMetadata.setStorageType(ValueMetaInterface.STORAGE_TYPE_NORMAL);
                storageMetadata.setLength(-1, -1); // we don't really know the lengths of the strings read in advance.
                valueMeta.setStorageMetadata(storageMetadata);

                valueMeta.setOrigin(name);

                inputRowMeta.addValueMeta(valueMeta);
            }
        } catch (Exception e) {

        }
    }

    @Override
    public void check(List<CheckResultInterface> remarks, TransMeta transMeta, StepMeta stepMeta, RowMetaInterface prev, String[] input, String[] output, RowMetaInterface info, VariableSpace space, Repository repository, IMetaStore metaStore) {
        if (prev == null || prev.size() == 0) {
            remarks.add(new CheckResult(CheckResultInterface.TYPE_RESULT_OK, "Not receiving any fields from previous steps.", stepMeta));
        } else {
            remarks.add(new CheckResult(CheckResultInterface.TYPE_RESULT_ERROR, String.format("Step is connected to previous one, receiving %1$d fields", prev.size()), stepMeta));
        }

        if (input.length > 0) {
            remarks.add( new CheckResult(CheckResultInterface.TYPE_RESULT_ERROR, "Step is receiving info from other steps!", stepMeta) );
        } else {
            remarks.add(new CheckResult(CheckResultInterface.TYPE_RESULT_OK, "No input received from other steps.", stepMeta));
        }
    }

    @Override
    public StepInterface getStep(StepMeta stepMeta, StepDataInterface stepDataInterface, int copyNr, TransMeta transMeta, Trans trans) {
        return new GoogleSpreadsheetInput(stepMeta, stepDataInterface, copyNr, transMeta, trans);
    }

    @Override
    public StepDataInterface getStepData() {
        return new GoogleSpreadsheetInputData();
    }
}
